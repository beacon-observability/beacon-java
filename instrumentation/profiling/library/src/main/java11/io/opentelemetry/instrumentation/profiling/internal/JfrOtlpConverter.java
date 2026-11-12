/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.instrumentation.profiling.internal;

import com.google.protobuf.ByteString;
import io.opentelemetry.proto.collector.profiles.v1development.ExportProfilesServiceRequest;
import io.opentelemetry.proto.common.v1.AnyValue;
import io.opentelemetry.proto.common.v1.ArrayValue;
import io.opentelemetry.proto.common.v1.InstrumentationScope;
import io.opentelemetry.proto.common.v1.KeyValue;
import io.opentelemetry.proto.profiles.v1development.Function;
import io.opentelemetry.proto.profiles.v1development.KeyValueAndUnit;
import io.opentelemetry.proto.profiles.v1development.Line;
import io.opentelemetry.proto.profiles.v1development.Link;
import io.opentelemetry.proto.profiles.v1development.Location;
import io.opentelemetry.proto.profiles.v1development.Mapping;
import io.opentelemetry.proto.profiles.v1development.Profile;
import io.opentelemetry.proto.profiles.v1development.ProfilesDictionary;
import io.opentelemetry.proto.profiles.v1development.ResourceProfiles;
import io.opentelemetry.proto.profiles.v1development.Sample;
import io.opentelemetry.proto.profiles.v1development.ScopeProfiles;
import io.opentelemetry.proto.profiles.v1development.Stack;
import io.opentelemetry.proto.profiles.v1development.ValueType;
import io.opentelemetry.sdk.resources.Resource;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import jdk.jfr.consumer.RecordedEvent;
import jdk.jfr.consumer.RecordedFrame;
import jdk.jfr.consumer.RecordedMethod;
import jdk.jfr.consumer.RecordedStackTrace;
import jdk.jfr.consumer.RecordingFile;

final class JfrOtlpConverter {
  private final ProfilesDictionary.Builder dictionary =
      ProfilesDictionary.newBuilder()
          .addMappingTable(Mapping.getDefaultInstance())
          .addLocationTable(Location.getDefaultInstance())
          .addFunctionTable(Function.getDefaultInstance())
          .addLinkTable(Link.getDefaultInstance())
          .addStringTable("")
          .addAttributeTable(KeyValueAndUnit.getDefaultInstance())
          .addStackTable(Stack.getDefaultInstance());
  private final Map<String, Integer> strings = new LinkedHashMap<>();
  private final Map<Function, Integer> functions = new LinkedHashMap<>();
  private final Map<Location, Integer> locations = new LinkedHashMap<>();
  private final Map<Stack, Integer> stacks = new LinkedHashMap<>();

  static ExportProfilesServiceRequest convert(
      Path file, Instant start, Instant end, Resource resource) throws IOException {
    return new JfrOtlpConverter().read(file, start, end, resource);
  }

  private ExportProfilesServiceRequest read(
      Path file, Instant start, Instant end, Resource resource) throws IOException {
    Map<String, Profile.Builder> profiles = new LinkedHashMap<>();
    try (RecordingFile recording = new RecordingFile(file)) {
      while (recording.hasMoreEvents()) {
        RecordedEvent event = recording.readEvent();
        Instant timestamp = event.getStartTime();
        if (timestamp.isBefore(start) || !timestamp.isBefore(end)) {
          continue;
        }
        String name = event.getEventType().getName();
        String type;
        String unit;
        boolean tlabAllocation = false;
        long value;
        if (name.equals("jdk.ExecutionSample") || name.equals("jdk.NativeMethodSample")) {
          type = "samples";
          unit = "count";
          value = 1;
        } else if (name.equals("jdk.ObjectAllocationSample")) {
          type = "allocation";
          unit = "bytes";
          value = event.getLong("weight");
        } else if (name.equals("jdk.ObjectAllocationInNewTLAB")
            || name.equals("jdk.ObjectAllocationOutsideTLAB")) {
          type = "allocation";
          unit = "bytes";
          value = event.getLong(name.endsWith("InNewTLAB") ? "tlabSize" : "allocationSize");
          tlabAllocation = true;
        } else if (name.equals("jdk.OldObjectSample")) {
          type = "retained_objects";
          unit = "count";
          value = 1;
        } else {
          continue;
        }
        RecordedStackTrace trace = event.getStackTrace();
        if (trace == null || trace.getFrames().isEmpty()) {
          continue;
        }
        String profileKey = tlabAllocation ? "tlab_allocation" : type;
        Profile.Builder profile = profiles.get(profileKey);
        if (profile == null) {
          UUID id = UUID.randomUUID();
          profile =
              Profile.newBuilder()
                  .setSampleType(
                      ValueType.newBuilder().setTypeStrindex(str(type)).setUnitStrindex(str(unit)))
                  .setTimeUnixNano(nanos(start))
                  .setDurationNano(Math.max(0, Duration.between(start, end).toNanos()))
                  .setProfileId(
                      ByteString.copyFrom(
                          ByteBuffer.allocate(16)
                              .putLong(id.getMostSignificantBits())
                              .putLong(id.getLeastSignificantBits())
                              .array()));
          profiles.put(profileKey, profile);
        }
        Stack.Builder stack = Stack.newBuilder();
        for (RecordedFrame frame : trace.getFrames()) {
          RecordedMethod method = frame.getMethod();
          String functionName =
              method.getType().getName() + "." + method.getName() + method.getDescriptor();
          Function function =
              Function.newBuilder()
                  .setNameStrindex(str(functionName))
                  .setSystemNameStrindex(str(functionName))
                  .build();
          Integer fn = functions.get(function);
          if (fn == null) {
            fn = dictionary.getFunctionTableCount();
            functions.put(function, fn);
            dictionary.addFunctionTable(function);
          }
          Location location =
              Location.newBuilder()
                  .addLines(
                      Line.newBuilder()
                          .setFunctionIndex(fn)
                          .setLine(Math.max(0, frame.getLineNumber())))
                  .build();
          Integer loc = locations.get(location);
          if (loc == null) {
            loc = dictionary.getLocationTableCount();
            locations.put(location, loc);
            dictionary.addLocationTable(location);
          }
          stack.addLocationIndices(loc);
        }
        Stack built = stack.build();
        Integer index = stacks.get(built);
        if (index == null) {
          index = dictionary.getStackTableCount();
          stacks.put(built, index);
          dictionary.addStackTable(built);
        }
        profile.addSamples(
            Sample.newBuilder()
                .setStackIndex(index)
                .addValues(value)
                .addTimestampsUnixNano(nanos(timestamp)));
      }
    }
    // Weighted samples and TLAB events overlap. Prefer samples from this window, regardless
    // of event order, and keep TLAB events only when no usable weighted sample was recorded.
    if (profiles.containsKey("allocation")) {
      profiles.remove("tlab_allocation");
    }
    io.opentelemetry.proto.resource.v1.Resource.Builder otlpResource =
        io.opentelemetry.proto.resource.v1.Resource.newBuilder();
    resource
        .getAttributes()
        .forEach(
            (key, value) -> {
              AnyValue.Builder any = AnyValue.newBuilder();
              switch (key.getType()) {
                case STRING:
                  any.setStringValue((String) value);
                  break;
                case LONG:
                  any.setIntValue((Long) value);
                  break;
                case BOOLEAN:
                  any.setBoolValue((Boolean) value);
                  break;
                case DOUBLE:
                  any.setDoubleValue((Double) value);
                  break;
                default:
                  ArrayValue.Builder array = ArrayValue.newBuilder();
                  for (Object item : (Iterable<?>) value) {
                    AnyValue.Builder entry = AnyValue.newBuilder();
                    if (item instanceof String) {
                      entry.setStringValue((String) item);
                    } else if (item instanceof Long) {
                      entry.setIntValue((Long) item);
                    } else if (item instanceof Boolean) {
                      entry.setBoolValue((Boolean) item);
                    } else if (item instanceof Double) {
                      entry.setDoubleValue((Double) item);
                    }
                    array.addValues(entry);
                  }
                  any.setArrayValue(array);
              }
              otlpResource.addAttributes(KeyValue.newBuilder().setKey(key.getKey()).setValue(any));
            });
    ScopeProfiles.Builder scope =
        ScopeProfiles.newBuilder()
            .setScope(InstrumentationScope.newBuilder().setName("io.opentelemetry.profiling"));
    profiles.values().forEach(scope::addProfiles);
    return ExportProfilesServiceRequest.newBuilder()
        .setDictionary(dictionary)
        .addResourceProfiles(
            ResourceProfiles.newBuilder().setResource(otlpResource).addScopeProfiles(scope))
        .build();
  }

  private int str(String value) {
    return strings.computeIfAbsent(
        value,
        key -> {
          int index = dictionary.getStringTableCount();
          dictionary.addStringTable(key);
          return index;
        });
  }

  private static long nanos(Instant value) {
    return Math.addExact(
        Math.multiplyExact(value.getEpochSecond(), 1_000_000_000L), value.getNano());
  }

  private JfrOtlpConverter() {
    strings.put("", 0);
  }
}

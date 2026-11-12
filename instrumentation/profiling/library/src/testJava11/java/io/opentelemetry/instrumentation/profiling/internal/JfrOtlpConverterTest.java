/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.instrumentation.profiling.internal;

import static org.assertj.core.api.Assertions.assertThat;

import io.opentelemetry.sdk.resources.Resource;
import java.io.IOException;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import jdk.jfr.AnnotationElement;
import jdk.jfr.Event;
import jdk.jfr.EventFactory;
import jdk.jfr.Name;
import jdk.jfr.Recording;
import jdk.jfr.StackTrace;
import jdk.jfr.ValueDescriptor;
import jdk.jfr.consumer.RecordingFile;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

class JfrOtlpConverterTest {
  private static final EventFactory SAMPLED =
      allocationEvent("jdk.ObjectAllocationSample", "weight");
  private static final EventFactory TLAB =
      allocationEvent("jdk.ObjectAllocationInNewTLAB", "tlabSize");
  private static final EventFactory OUTSIDE_TLAB =
      allocationEvent("jdk.ObjectAllocationOutsideTLAB", "allocationSize");

  @TempDir Path directory;

  @ParameterizedTest
  @CsvSource({"true,false,100", "false,false,50", "true,true,50"})
  void selectsOneAllocationSourcePerSnapshot(
      boolean sampled, boolean sampleBeforeWindow, long expectedBytes) throws IOException {
    Path path = directory.resolve("allocations.jfr");
    try (Recording recording = new Recording()) {
      recording.enable(Long.toString(SAMPLED.getEventType().getId())).withStackTrace();
      recording.enable(Long.toString(TLAB.getEventType().getId())).withStackTrace();
      recording.enable(Long.toString(OUTSIDE_TLAB.getEventType().getId())).withStackTrace();
      recording.start();
      Instant start = recording.getStartTime();
      if (sampled) {
        Event event = SAMPLED.newEvent();
        event.set(0, 100L);
        event.commit();
      }
      Event tlab = TLAB.newEvent();
      tlab.set(0, 20L);
      tlab.commit();
      Event outside = OUTSIDE_TLAB.newEvent();
      outside.set(0, 30L);
      outside.commit();
      recording.stop();
      recording.dump(path);

      var events = RecordingFile.readAllEvents(path);
      assertThat(events)
          .isNotEmpty()
          .allSatisfy(event -> assertThat(event.getStackTrace()).isNotNull());
      if (sampleBeforeWindow) {
        // Use the JFR clock boundary, avoiding wall-clock precision differences.
        start =
            events.stream()
                .filter(
                    event -> event.getEventType().getName().equals("jdk.ObjectAllocationSample"))
                .findFirst()
                .orElseThrow()
                .getStartTime()
                .plusNanos(1);
      }
      var request =
          JfrOtlpConverter.convert(path, start, recording.getStopTime(), Resource.empty());
      var profiles = request.getResourceProfiles(0).getScopeProfiles(0).getProfilesList();
      assertThat(profiles).hasSize(1);
      var profile = profiles.get(0);
      assertThat(request.getDictionary().getStringTable(profile.getSampleType().getTypeStrindex()))
          .isEqualTo("allocation");
      assertThat(request.getDictionary().getStringTable(profile.getSampleType().getUnitStrindex()))
          .isEqualTo("bytes");
      assertThat(profile.getSamplesList().stream().mapToLong(value -> value.getValues(0)).sum())
          .isEqualTo(expectedBytes);
      assertThat(profile.getSamplesList()).hasSize(expectedBytes == 100 ? 1 : 2);
    }
  }

  private static EventFactory allocationEvent(String name, String field) {
    return EventFactory.create(
        List.of(
            new AnnotationElement(Name.class, name), new AnnotationElement(StackTrace.class, true)),
        List.of(new ValueDescriptor(long.class, field)));
  }
}

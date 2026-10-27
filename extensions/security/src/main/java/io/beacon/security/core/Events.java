/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.beacon.security.core;

import static io.beacon.security.core.Values.map;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Arrays.asList;
import static java.util.Collections.emptyList;

import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeFormatterBuilder;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeSet;

public final class Events {
  public static final int SCHEMA_VERSION = 2;
  public static final int FINGERPRINT_VERSION = 1;
  public static final String PRODUCT = "io.beacon.security";

  private static final DateTimeFormatter TIMESTAMP =
      new DateTimeFormatterBuilder().appendInstant(3).toFormatter(Locale.ROOT);

  private Events() {}

  public static String timestamp(long epochMillis) {
    return TIMESTAMP.format(Instant.ofEpochMilli(epochMillis));
  }

  public static String now() {
    return timestamp(System.currentTimeMillis());
  }

  public static Map<String, Object> sink(
      String rule, String role, String function, String location) {
    String normalized = role;
    if (role.equals("template")) {
      normalized = "sql_template";
    } else if (role.equals("shell") || role.equals("shell_command")) {
      normalized = "shell_script";
    } else if (role.equals("argv") || role.equals("ordinary_argument")) {
      normalized = "argument";
    } else if (role.equals("unknown_target")) {
      normalized = "destination_unknown";
    } else if (role.equals("request_path")
        || role.equals("request_query")
        || role.equals("path_query")) {
      normalized = "path_or_query";
    }
    Map<String, Object> sink =
        map(
            "function",
            function,
            "role",
            normalized,
            "location",
            location,
            "operation",
            "",
            "path_role",
            "",
            "input_part",
            "");
    if (rule.equals("http_request_input")) {
      sink.put(
          "input_part",
          role.equals("request_path")
              ? "path"
              : role.equals("request_query") ? "query" : "path_or_query");
    }
    if (rule.equals("path_traversal")) {
      sink.put("role", "file_path");
      String name = function.toLowerCase(Locale.ROOT);
      String operation = "unknown";
      if (name.matches(".*(?:copy|\\.cp(?:sync)?$|\\.link(?:sync)?$).*")) {
        operation = "copy";
      } else if (name.matches(".*(?:rename|\\.move$).*")) {
        operation = "rename";
      } else if (name.matches(".*(?:delete|unlink|rmdir|\\.rm(?:sync)?$).*")) {
        operation = "delete";
      } else if (asList("read", "write", "delete", "rename").contains(role)) {
        operation = role;
      } else if (role.equals("source")
          || name.matches(".*(?:inputstream|reader|directorystream|\\.read).*")) {
        operation = "read";
      } else if (role.equals("target") || name.matches(".*(?:outputstream|writer|\\.write).*")) {
        operation = "write";
      }
      sink.put("operation", operation);
      String pathRole = "unknown";
      if (role.equals("source") || role.equals("read")) {
        pathRole = "source";
      } else if (asList("target", "write", "delete", "destination_path").contains(role)) {
        pathRole = "target";
      } else if (role.equals("file_path") && asList("copy", "rename", "read").contains(operation)) {
        pathRole = "source";
      } else if (role.equals("file_path") && asList("write", "delete").contains(operation)) {
        pathRole = "target";
      }
      sink.put("path_role", pathRole);
    }
    return sink;
  }

  public static String fingerprint(
      String serviceScope,
      String language,
      String rule,
      Map<String, Object> sink,
      Iterable<String> signatures) {
    try {
      MessageDigest hash = MessageDigest.getInstance("SHA-256");
      List<String> parts = new ArrayList<>(asList("1", serviceScope, language, rule));
      for (String field :
          asList("role", "function", "location", "operation", "path_role", "input_part")) {
        parts.add(String.valueOf(sink.get(field)));
      }
      TreeSet<String> sorted = new TreeSet<>();
      for (String signature : signatures) {
        sorted.add(signature);
      }
      parts.addAll(sorted);
      for (String part : parts) {
        byte[] value = unicode(part).getBytes(UTF_8);
        hash.update(ByteBuffer.allocate(4).putInt(value.length).array());
        hash.update(value);
      }
      StringBuilder result = new StringBuilder("finding-");
      for (byte value : hash.digest()) {
        result
            .append(Character.forDigit((value >>> 4) & 15, 16))
            .append(Character.forDigit(value & 15, 16));
      }
      return result.toString();
    } catch (NoSuchAlgorithmException error) {
      throw new IllegalStateException(error);
    }
  }

  private static String unicode(String value) {
    StringBuilder result = new StringBuilder(value.length());
    for (int i = 0; i < value.length(); i++) {
      char c = value.charAt(i);
      if (Character.isHighSurrogate(c)
          && i + 1 < value.length()
          && Character.isLowSurrogate(value.charAt(i + 1))) {
        result.append(c).append(value.charAt(++i));
      } else {
        result.append(Character.isSurrogate(c) ? (char) 0xfffd : c);
      }
    }
    return result.toString();
  }

  public static String traceId(Object value, int length) {
    String text = value == null ? "" : String.valueOf(value).toLowerCase(Locale.ROOT);
    return text.length() == length && text.matches("[0-9a-f]+") && !text.matches("0+") ? text : "";
  }

  public static Map<String, Object> request(Map<String, Object> value) {
    Map<String, Object> request =
        map(
            "method",
            "",
            "route",
            "",
            "route_status",
            "unavailable",
            "status_code",
            null,
            "started_at",
            null,
            "ended_at",
            null,
            "framework",
            "",
            "transport",
            "",
            "error_type",
            "");
    if (value != null) {
      request.putAll(value);
    }
    return request;
  }

  // Identity and request maps are created by Beacon before they enter this normalizer.
  @SuppressWarnings("unchecked")
  public static Map<String, Object> record(Map<String, Object> input) {
    Map<String, Object> event = new LinkedHashMap<>(input);
    if ("beacon.security.sbom.inventory".equals(event.get("event_name"))) {
      event
          .keySet()
          .retainAll(
              asList(
                  "event_name",
                  "instance_id",
                  "observed_at",
                  "started_at",
                  "uptime_ms",
                  "dependencies",
                  "part_index",
                  "part_count"));
      event.put("schema_version", SCHEMA_VERSION);
      event.put("source", "beacon_security_sbom");
      event.putIfAbsent("instance_id", Identity.INSTANCE);
      event.putIfAbsent("observed_at", now());
      return event;
    }
    Map<String, Object> identity = new LinkedHashMap<>(Identity.context());
    Object nested = event.remove("identity");
    if (nested instanceof Map) {
      identity.putAll((Map<String, Object>) nested);
    }
    identity.forEach(event::putIfAbsent);
    event.put("schema_version", SCHEMA_VERSION);
    event.putIfAbsent("observed_at", now());
    String name = String.valueOf(event.get("event_name"));
    event.put("source", "beacon_security");
    if (name.equals("beacon.security.finding")) {
      event.put("request", request((Map<String, Object>) event.get("request")));
      String trace = traceId(event.get("trace_id"), 32);
      String server = trace.isEmpty() ? "" : traceId(event.get("server_span_id"), 16);
      event.put("trace_id", trace);
      event.put("server_span_id", server);
      event.put(
          "current_span_id", trace.isEmpty() ? "" : traceId(event.get("current_span_id"), 16));
      Object flags = event.get("trace_flags");
      event.put(
          "trace_flags",
          !server.isEmpty() && flags instanceof Number ? ((Number) flags).intValue() & 255 : 0);
      event.put("trace_availability", "not_guaranteed_by_trace_id");
      event.putIfAbsent("attack_evidence", AttackEvidence.unknown("analysis_unavailable").fields());
      Object component = event.get("component");
      if (!(component instanceof Map) || ((Map<?, ?>) component).isEmpty()) {
        event.remove("component");
      }
      event.putIfAbsent("stack", emptyList());
    }
    return event;
  }

  // Project only at the export boundary: internal matching, sampling and fingerprints stay intact.
  @SuppressWarnings("unchecked")
  public static Map<String, Object> exported(Map<String, Object> input) {
    if (!"beacon.security.finding".equals(input.get("event_name"))) {
      return input;
    }
    Map<String, Object> event =
        fields(
            input,
            "schema_version",
            "source",
            "event_name",
            "instance_id",
            "observed_at",
            "finding_id",
            "occurrence_id",
            "fingerprint_version",
            "rule",
            "precision",
            "trace_id",
            "server_span_id",
            "current_span_id",
            "sources",
            "propagation",
            "ranges",
            "stack",
            "component",
            "collection_complete",
            "truncated",
            "coverage_gaps",
            "truncation_reason",
            "evidence_sampled",
            "evidence_sample_reason",
            "run",
            "triage");
    for (String name : asList("attack_evidence", "request", "sink")) {
      Object nested = input.get(name);
      if (nested instanceof Map) {
        String[] keys =
            name.equals("attack_evidence")
                ? new String[] {"status", "reason"}
                : name.equals("request")
                    ? new String[] {"method", "route", "status_code", "error_type"}
                    : new String[] {
                      "function", "role", "location", "operation", "path_role", "input_part"
                    };
        Map<String, Object> value = fields((Map<String, Object>) nested, keys);
        if (!value.isEmpty()) {
          event.put(name, value);
        }
      }
    }
    if (event.get("server_span_id") != null
        && event.get("server_span_id").equals(event.get("current_span_id"))) {
      event.remove("current_span_id");
    }
    if (Boolean.FALSE.equals(event.get("truncated"))) {
      event.remove("truncated");
    }
    if (Boolean.TRUE.equals(event.get("evidence_sampled"))) {
      event.remove("evidence_sample_reason");
    }
    return event;
  }

  private static Map<String, Object> fields(Map<String, Object> input, String... names) {
    Map<String, Object> result = new LinkedHashMap<>();
    for (String name : names) {
      Object value = input.get(name);
      if (value != null
          && !"".equals(value)
          && (!(value instanceof Map) || !((Map<?, ?>) value).isEmpty())
          && (!(value instanceof List) || !((List<?>) value).isEmpty())) {
        result.put(name, value);
      }
    }
    return result;
  }
}

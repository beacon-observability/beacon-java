/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.beacon.security.core;

import static io.beacon.security.core.Values.map;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Arrays.asList;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Pattern;

/** Moves event time and occurrence identity out of the compact Security JSON Body. */
public final class SecurityLogRecord {
  public static final String PROFILE = "beacon-security-log-record-v1";
  private static final Pattern EVENT_TIME =
      Pattern.compile("\\d{4}-\\d{2}-\\d{2}T(?:[01]\\d|2[0-3]):[0-5]\\d:[0-5]\\d(?:\\.\\d{1,9})?Z");

  public final byte[] body;
  public final long timeUnixNano;
  public final String eventId;

  private SecurityLogRecord(byte[] body, long timeUnixNano, String eventId) {
    this.body = body;
    this.timeUnixNano = timeUnixNano;
    this.eventId = eventId;
  }

  public static byte[] encodeBody(ObjectMapper json, Map<String, Object> event) throws IOException {
    Map<String, Object> body = new LinkedHashMap<>(event);
    body.remove("observed_at");
    body.remove("occurrence_id");
    return json.writeValueAsBytes(body);
  }

  public static SecurityLogRecord create(ObjectMapper json, Map<String, Object> event, byte[] body)
      throws IOException {
    if (text(event, "instance_id").isEmpty()) {
      throw new IOException("security_instance_id_missing");
    }
    if (event.containsKey("server_span_id") || event.containsKey("current_span_id")) {
      throw new IOException("removed_security_span_field");
    }
    Object flags = event.get("trace_flags");
    if (flags != null
        && (!(flags instanceof Number)
            || ((Number) flags).doubleValue() < 0
            || ((Number) flags).doubleValue() > 255
            || ((Number) flags).doubleValue() != Math.rint(((Number) flags).doubleValue()))) {
      throw new IOException("invalid_security_trace_flags");
    }
    String observed = text(event, "observed_at");
    long nanos;
    try {
      // Instant arithmetic retains nanoseconds; toEpochMilli would discard sub-ms precision.
      if (!EVENT_TIME.matcher(observed).matches()) {
        throw new IOException("invalid_security_event_time");
      }
      Instant instant = Instant.parse(observed);
      nanos =
          Math.addExact(
              Math.multiplyExact(instant.getEpochSecond(), 1000000000L), instant.getNano());
      if (nanos <= 0) {
        throw new IOException("invalid_security_event_time");
      }
    } catch (DateTimeParseException | ArithmeticException error) {
      throw new IOException("invalid_security_event_time", error);
    }
    String id = text(event, "occurrence_id");
    if ("beacon.security.sbom.inventory".equals(event.get("event_name"))) {
      String index = text(event, "part_index");
      id =
          "inventory-"
              + Identity.digest(
                  json.writeValueAsString(
                      asList(
                          text(event, "source"),
                          text(event, "event_name"),
                          text(event, "instance_id"),
                          observed,
                          index.isEmpty() ? "0" : index)));
    } else if (id.isEmpty()) {
      throw new IOException("security_occurrence_id_missing");
    }
    return new SecurityLogRecord(body, nanos, id);
  }

  /** A file-only logical record; this wrapper is never sent as the OTel Body. */
  public byte[] diagnostic(ObjectMapper json, Map<String, Object> event) throws IOException {
    return json.writeValueAsBytes(
        map(
            "time_unix_nano", Long.toString(timeUnixNano),
            "body", new String(body, UTF_8),
            "attributes",
                map(
                    "event_id",
                    eventId,
                    "source",
                    event.get("source"),
                    "event.name",
                    event.get("event_name"))));
  }

  private static String text(Map<String, ?> values, String key) {
    Object value = values.get(key);
    String text = value == null ? "" : String.valueOf(value);
    return text.trim().isEmpty() ? "" : text;
  }
}

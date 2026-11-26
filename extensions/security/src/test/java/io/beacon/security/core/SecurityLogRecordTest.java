/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.beacon.security.core;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Arrays.asList;
import static java.util.Objects.requireNonNull;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.io.InputStream;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Properties;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

class SecurityLogRecordTest {
  private static final ObjectMapper json = new ObjectMapper();

  @ParameterizedTest
  @ValueSource(
      strings = {
        "finding",
        "finding-occurrence",
        "sbom-inventory",
        "sbom-part-0",
        "sbom-part-1",
        "sbom-empty"
      })
  void matchesPinnedBindingWithoutDuplicatingMetadata(String name) throws IOException {
    Map<String, Object> event = fixture("inputs/" + name);
    Map<String, Object> original = new LinkedHashMap<>(event);
    Map<String, Object> expected = fixture(name);
    SecurityLogRecord record = record(event);
    Map<String, Object> actual = parse(record.diagnostic(json, event));
    assertThat(actual).isEqualTo(expected);
    Map<String, Object> body = parse(record.body);
    event.remove("observed_at");
    event.remove("occurrence_id");
    assertThat(body)
        .isEqualTo(event)
        .doesNotContainKeys("message", "observed_at", "occurrence_id", "event_id");
    assertThat(new String(record.body, UTF_8)).doesNotContain("\n", "\r");
    assertThat(record(original).eventId).isEqualTo(record.eventId);
  }

  @ParameterizedTest
  @CsvSource({
    "2026-10-02T00:00:00.000Z,1790899200000000000",
    "2026-10-02T00:00:00.123456789Z,1790899200123456789",
    "1970-01-01T00:00:00.000000001Z,1",
    "2262-04-11T23:47:16.854775807Z,9223372036854775807"
  })
  void preservesExactNativeNanoseconds(String observed, long expected) throws IOException {
    Map<String, Object> event = fixture("inputs/finding");
    event.put("observed_at", observed);
    assertThat(record(event).timeUnixNano).isEqualTo(expected);
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "",
        "invalid",
        "2026-02-30T00:00:00Z",
        "2026-10-02T24:00:00Z",
        "2026-10-02T23:59:60Z",
        "1970-01-01T00:00:00Z",
        "1969-12-31T23:59:59Z",
        "2262-04-11T23:47:16.854775808Z",
        "2026-10-02T00:00:00.1234567891Z"
      })
  void rejectsUnsetInvalidOrOverflowingTime(String observed) throws IOException {
    Map<String, Object> event = fixture("inputs/finding");
    event.put("observed_at", observed);
    assertThatThrownBy(() -> record(event))
        .isInstanceOf(IOException.class)
        .hasMessage("invalid_security_event_time");
  }

  @Test
  void retainsNestedEvidenceAndEscapedUnicodeWithoutAWrapper() throws IOException {
    Map<String, Object> event = fixture("inputs/finding");
    event.put("stack", asList("订单\\目录\"query\"\n下一行\r末尾", "🚀"));
    Map<String, Object> original = new LinkedHashMap<>(event);
    SecurityLogRecord record = record(event);
    assertThat(parse(record.body).get("stack")).isEqualTo(event.get("stack"));
    assertThat(new String(record.body, UTF_8)).doesNotContain("\n", "\r");
    assertThat(event).isEqualTo(original);
  }

  @Test
  void inventoryIdsRemainStableAcrossRetriesAndDifferAcrossRoundsAndParts() throws IOException {
    Map<String, Object> event = fixture("inputs/sbom-inventory");
    String initial = record(event).eventId;
    event.put("part_index", 0);
    assertThat(record(event).eventId).isEqualTo(initial);
    event.put("part_index", 1);
    assertThat(record(event).eventId).isNotEqualTo(initial);
    event.remove("part_index");
    event.put("observed_at", "2026-10-02T00:25:00.000Z");
    assertThat(record(event).eventId).isNotEqualTo(initial);
  }

  @Test
  void rejectsMissingOccurrenceIdentityInsteadOfInventingIt() throws IOException {
    Map<String, Object> event = fixture("inputs/finding");
    event.remove("occurrence_id");
    assertThatThrownBy(() -> record(event))
        .isInstanceOf(IOException.class)
        .hasMessage("security_occurrence_id_missing");
  }

  @Test
  void rejectsMissingProcessIdentityAndStringFlags() throws IOException {
    Map<String, Object> event = fixture("inputs/finding");
    event.remove("instance_id");
    assertThatThrownBy(() -> record(event))
        .isInstanceOf(IOException.class)
        .hasMessage("security_instance_id_missing");
    event.put("instance_id", Identity.INSTANCE);
    event.put("trace_flags", "1");
    assertThatThrownBy(() -> record(event))
        .isInstanceOf(IOException.class)
        .hasMessage("invalid_security_trace_flags");
  }

  @Test
  void pinsWireBindingSeparatelyFromLogicalEventSchema() throws IOException {
    Properties properties = new Properties();
    try (InputStream stream =
        requireNonNull(
            getClass().getResourceAsStream("/META-INF/beacon/security-version.properties"))) {
      properties.load(stream);
    }
    assertThat(properties.getProperty("wire.profile")).isEqualTo(SecurityLogRecord.PROFILE);
    assertThat(System.getProperty("beacon.security.spec.wire-profile"))
        .isEqualTo(SecurityLogRecord.PROFILE);
    assertThat(properties.getProperty("schema.version")).isEqualTo("2");
  }

  private static SecurityLogRecord record(Map<String, Object> event) throws IOException {
    return SecurityLogRecord.create(json, event, SecurityLogRecord.encodeBody(json, event));
  }

  private static Map<String, Object> fixture(String name) throws IOException {
    try (InputStream stream =
        requireNonNull(
            SecurityLogRecordTest.class.getResourceAsStream("/log-record-v1/" + name + ".json"))) {
      return json.readValue(stream, new TypeReference<Map<String, Object>>() {});
    }
  }

  private static Map<String, Object> parse(byte[] value) throws IOException {
    return json.readValue(value, new TypeReference<Map<String, Object>>() {});
  }
}

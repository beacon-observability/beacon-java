/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.beacon.security.core;

import static io.beacon.security.core.Values.map;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Arrays.asList;
import static java.util.Collections.emptyMap;
import static java.util.Collections.singletonMap;
import static java.util.Objects.requireNonNull;
import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.io.InputStream;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Properties;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class SiemEventTest {
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
  void matchesPinnedUnenrichedProfileVectors(String name) throws IOException {
    Map<String, Object> expected = fixture(name);
    String message = (String) expected.get("message");
    Map<String, Object> event = parse(message);
    Map<String, String> resource = singletonMap("service.name", (String) expected.get("service"));

    Map<String, Object> actual = parse(SiemEvent.encode(json, event, message, resource));

    assertThat(actual).isEqualTo(expected);
    assertThat(actual.keySet())
        .containsExactlyElementsOf(
            asList(
                "time",
                "event_id",
                "event_class",
                "source",
                "service",
                "tenant_id",
                "actor",
                "ip",
                "action",
                "target",
                "target_type",
                "outcome",
                "status",
                "severity",
                "message"));
    assertThat(actual.get("message")).isEqualTo(message);
    assertThat(parse((String) actual.get("message"))).isEqualTo(event);
  }

  @Test
  void retainsWhitespaceEscapesAndUnicodeInOriginalMessage() throws IOException {
    String message =
        " \n"
            + ((String) fixture("finding").get("message"))
                .replace("sql_injection", "sql_\\u0069njection")
                .replace("Orders.java", "订单.java")
            + "\t\n";
    Map<String, Object> event = parse(message);
    Map<String, Object> actual = parse(SiemEvent.encode(json, event, message, emptyMap()));

    assertThat(actual.get("message")).isEqualTo(message);
    assertThat(actual.get("action")).isEqualTo("sql_injection");
    assertThat(actual.get("service")).isEqualTo("");
    assertThat(actual.get("tenant_id")).isEqualTo("default");
    assertThat(actual.get("actor")).isEqualTo("");
    assertThat(actual.get("ip")).isEqualTo("");
  }

  @ParameterizedTest
  @ValueSource(strings = {"", " ", "configured-tenant"})
  void usesConfiguredTenantOrDefaultWithoutCollectingRequestIdentity(String tenant)
      throws IOException {
    Map<String, Object> event = parse((String) fixture("finding").get("message"));
    Map<String, String> resource = new LinkedHashMap<>();
    resource.put("service.name", "orders");
    resource.put("tenant.id", tenant);

    Map<String, Object> actual =
        parse(SiemEvent.encode(json, event, json.writeValueAsString(event), resource));

    assertThat(actual.get("service")).isEqualTo("orders");
    assertThat(actual.get("tenant_id")).isEqualTo(tenant.trim().isEmpty() ? "default" : tenant);
    assertThat(actual.get("actor")).isEqualTo("");
    assertThat(actual.get("ip")).isEqualTo("");
  }

  @ParameterizedTest
  @ValueSource(strings = {"unknown", "no_evidence", "suspected"})
  void doesNotTreatClassificationOrHttpSuccessAsExecutionOutcome(String status) throws IOException {
    Map<String, Object> event = parse((String) fixture("finding").get("message"));
    event.put("attack_evidence", map("status", status, "reason", "test"));
    event.put("request", map("status_code", 200));
    event.put("triage", map("decision", "accepted_risk"));

    Map<String, Object> actual =
        parse(SiemEvent.encode(json, event, json.writeValueAsString(event), emptyMap()));

    assertThat(actual.get("outcome")).isEqualTo("unknown");
    assertThat(actual.get("status")).isEqualTo("info");
    assertThat(actual.get("severity")).isEqualTo("informational");
    assertThat(actual.get("event_id")).isEqualTo(event.get("occurrence_id"));
    assertThat(actual.get("target")).isEqualTo(event.get("finding_id"));
  }

  @Test
  void inventoryIdsAreStableAcrossRetransmissionAndDistinctAcrossPartsAndRounds()
      throws IOException {
    Map<String, Object> event = parse((String) fixture("sbom-inventory").get("message"));
    Object initial = projected(event).get("event_id");
    event.put("part_index", 0);
    assertThat(projected(event).get("event_id")).isEqualTo(initial);
    event.put("part_index", 1);
    assertThat(projected(event).get("event_id")).isNotEqualTo(initial);
    event.remove("part_index");
    event.put("observed_at", "2026-10-02T00:25:00.000Z");
    assertThat(projected(event).get("event_id")).isNotEqualTo(initial);
  }

  @Test
  void recordsProfileIndependentlyOfEmbeddedPayloadSchema() throws IOException {
    Properties properties = new Properties();
    try (InputStream stream =
        requireNonNull(
            getClass().getResourceAsStream("/META-INF/beacon/security-version.properties"))) {
      properties.load(stream);
    }
    assertThat(properties.getProperty("wire.profile")).isEqualTo(SiemEvent.PROFILE);
    assertThat(System.getProperty("beacon.security.spec.wire-profile"))
        .isEqualTo(SiemEvent.PROFILE);
    assertThat(properties.getProperty("schema.version")).isEqualTo("2");
  }

  private static Map<String, Object> projected(Map<String, Object> event) throws IOException {
    return parse(SiemEvent.encode(json, event, json.writeValueAsString(event), emptyMap()));
  }

  private static Map<String, Object> fixture(String name) throws IOException {
    try (InputStream stream =
        requireNonNull(SiemEventTest.class.getResourceAsStream("/siem-v1/" + name + ".json"))) {
      return json.readValue(stream, new TypeReference<Map<String, Object>>() {});
    }
  }

  private static Map<String, Object> parse(byte[] bytes) throws IOException {
    return parse(new String(bytes, UTF_8));
  }

  private static Map<String, Object> parse(String value) throws IOException {
    return json.readValue(value, new TypeReference<Map<String, Object>>() {});
  }
}

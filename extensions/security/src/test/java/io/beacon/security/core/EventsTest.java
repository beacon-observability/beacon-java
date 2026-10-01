/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.beacon.security.core;

import static io.beacon.security.core.Values.map;
import static java.util.Arrays.asList;
import static java.util.Collections.emptyMap;
import static org.assertj.core.api.Assertions.assertThat;

import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class EventsTest {

  @AfterEach
  void resetIdentity() {
    Identity.configure(emptyMap());
    System.clearProperty("beacon.security.enabled");
  }

  @Test
  void recordsFirstBeaconSecurityContract() {
    Identity.configure(
        mapOfStrings(
            "service.name", "orders", "service.namespace", "shop", "service.version", "1.2.3"));

    Map<String, Object> event =
        Events.record(
            map(
                "event_name",
                "beacon.security.finding",
                "trace_id",
                "11111111111111111111111111111111",
                "server_span_id",
                "2222222222222222",
                "current_span_id",
                "3333333333333333",
                "trace_flags",
                1));

    assertThat(event)
        .containsEntry("schema_version", 1)
        .containsEntry("source", "beacon_security")
        .containsEntry("event_name", "beacon.security.finding")
        .containsEntry("trace_id", "11111111111111111111111111111111")
        .containsEntry("server_span_id", "2222222222222222")
        .containsEntry("current_span_id", "3333333333333333")
        .containsEntry("trace_flags", 1);
    assertThat(event.get("application_id")).isEqualTo("app-" + Identity.digest("shop|orders"));
    assertThat(Events.PRODUCT).isEqualTo("io.beacon.security");
  }

  @Test
  void fingerprintVersionStartsAtOne() {
    Map<String, Object> sink =
        Events.sink("sql_injection", "query", "java.sql.Statement.execute", "Example.java:12");

    String first =
        Events.fingerprint(
            "orders", "java", "sql_injection", sink, asList("parameter|name", "header|x"));
    String second =
        Events.fingerprint(
            "orders", "java", "sql_injection", sink, asList("header|x", "parameter|name"));

    assertThat(Events.SCHEMA_VERSION).isEqualTo(1);
    assertThat(Events.FINGERPRINT_VERSION).isEqualTo(1);
    assertThat(first).startsWith("finding-").isEqualTo(second);
  }

  @Test
  void buildProvidesBeaconVersionToEmbeddedExtension() {
    assertThat(Identity.VERSION).isNotBlank().isNotEqualTo("development");
  }

  @Test
  void securityIsDisabledByDefault() {
    assertThat(Settings.enabled("beacon.security.enabled", false)).isFalse();

    System.setProperty("beacon.security.enabled", "true");

    assertThat(Settings.enabled("beacon.security.enabled", false)).isTrue();
  }

  private static Map<String, String> mapOfStrings(String... entries) {
    LinkedHashMap<String, String> result = new LinkedHashMap<>();
    for (int i = 0; i < entries.length; i += 2) {
      result.put(entries[i], entries[i + 1]);
    }
    return result;
  }
}

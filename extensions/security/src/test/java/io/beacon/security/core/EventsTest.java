/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.beacon.security.core;

import static io.beacon.security.core.Values.map;
import static java.util.Arrays.asList;
import static java.util.Collections.emptyList;
import static java.util.Collections.emptyMap;
import static org.assertj.core.api.Assertions.assertThat;

import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class EventsTest {

  @AfterEach
  void resetIdentity() {
    Identity.configure(emptyMap());
    System.clearProperty("beacon.security.enabled");
  }

  @Test
  void recordsRuntimeIdentityContract() {
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
        .containsEntry("schema_version", 2)
        .containsEntry("instance_id", Identity.INSTANCE)
        .doesNotContainKey("application_id")
        .containsEntry("source", "beacon_security")
        .containsEntry("event_name", "beacon.security.finding")
        .containsEntry("trace_id", "11111111111111111111111111111111")
        .containsEntry("server_span_id", "2222222222222222")
        .containsEntry("current_span_id", "3333333333333333")
        .containsEntry("trace_flags", 1);
    assertThat(event).doesNotContainKey("component");
    assertThat(Identity.findingScope()).isEqualTo("app-" + Identity.digest("shop|orders"));
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

    assertThat(Events.SCHEMA_VERSION)
        .isEqualTo(Integer.parseInt(System.getProperty("beacon.security.spec.schema-version")));
    assertThat(Events.FINGERPRINT_VERSION)
        .isEqualTo(
            Integer.parseInt(System.getProperty("beacon.security.spec.fingerprint-version")));
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

  @ParameterizedTest
  @ValueSource(strings = {"unknown", "no_evidence", "suspected"})
  void exportsClassificationWithoutFixedOutcomeOrResourceDuplicates(String status) {
    Map<String, Object> original =
        Events.record(
            map(
                "event_name", "beacon.security.finding",
                "attack_evidence",
                    map("status", status, "reason", "test_reason", "outcome", "not_assessed"),
                "finding_id", "finding-stable",
                "occurrence_id", "ev-once",
                "assessment", "candidate_risk",
                "validation", "unvalidated",
                "severity", "unassigned",
                "confidence", "modeled_flow",
                "precision", "exact",
                "execution_observation", "invocation_attempt",
                "coverage", "modeled_calls_only",
                "collection_complete", true,
                "evidence_sampled", true,
                "evidence_sample_reason", "evidence_upgrade",
                "request",
                    map(
                        "method",
                        "GET",
                        "route",
                        "/orders",
                        "status_code",
                        200,
                        "started_at",
                        "2026-10-27T12:00:00Z"),
                "sink",
                    map(
                        "function",
                        "Statement.execute",
                        "role",
                        "sql_template",
                        "location",
                        "Orders.java:12",
                        "operation",
                        ""),
                "stack", asList("Orders.query(Orders.java:12)")));
    Map<String, Object> exported = Events.exported(original);

    assertThat(exported)
        .containsEntry("finding_id", "finding-stable")
        .containsEntry("occurrence_id", "ev-once")
        .containsEntry("attack_evidence", map("status", status, "reason", "test_reason"))
        .containsEntry("request", map("method", "GET", "route", "/orders", "status_code", 200))
        .containsEntry(
            "sink",
            map(
                "function",
                "Statement.execute",
                "role",
                "sql_template",
                "location",
                "Orders.java:12"))
        .containsEntry("precision", "exact")
        .containsEntry("stack", asList("Orders.query(Orders.java:12)"))
        .doesNotContainKeys(
            "service",
            "runtime",
            "code",
            "identity_status",
            "assessment",
            "validation",
            "severity",
            "confidence",
            "execution_observation",
            "coverage",
            "trace_flags",
            "trace_availability",
            "evidence_sample_reason");
    assertThat(original)
        .containsEntry(
            "attack_evidence",
            map("status", status, "reason", "test_reason", "outcome", "not_assessed"))
        .containsEntry("assessment", "candidate_risk");
    assertThat(original.get("request"))
        .isEqualTo(
            Events.request(
                map(
                    "method",
                    "GET",
                    "route",
                    "/orders",
                    "status_code",
                    200,
                    "started_at",
                    "2026-10-27T12:00:00Z")));
  }

  @Test
  void omitsEmptyEvidenceButKeepsQualityFlagsAndDistinctSpanCorrelation() {
    Map<String, Object> input =
        map(
            "event_name",
            "beacon.security.finding",
            "server_span_id",
            "1111111111111111",
            "current_span_id",
            "1111111111111111",
            "sources",
            emptyList(),
            "ranges",
            emptyList(),
            "propagation",
            emptyList(),
            "stack",
            emptyList(),
            "truncated",
            false,
            "collection_complete",
            false,
            "coverage_gaps",
            asList("unmodeled_call"),
            "evidence_sampled",
            false,
            "evidence_sample_reason",
            "interval");
    assertThat(Events.exported(input))
        .containsEntry("collection_complete", false)
        .containsEntry("coverage_gaps", asList("unmodeled_call"))
        .containsEntry("evidence_sampled", false)
        .containsEntry("evidence_sample_reason", "interval")
        .doesNotContainKeys(
            "sources", "ranges", "propagation", "stack", "truncated", "current_span_id");

    input.put("current_span_id", "2222222222222222");
    input.put("truncated", true);
    input.put("truncation_reason", "record_byte_limit");
    assertThat(Events.exported(input))
        .containsEntry("current_span_id", "2222222222222222")
        .containsEntry("truncated", true)
        .containsEntry("truncation_reason", "record_byte_limit");
  }

  private static Map<String, String> mapOfStrings(String... entries) {
    LinkedHashMap<String, String> result = new LinkedHashMap<>();
    for (int i = 0; i < entries.length; i += 2) {
      result.put(entries[i], entries[i + 1]);
    }
    return result;
  }
}

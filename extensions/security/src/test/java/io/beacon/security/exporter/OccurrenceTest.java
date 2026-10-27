/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.beacon.security.exporter;

import static java.util.Collections.emptyMap;
import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.beacon.security.core.AttackEvidence;
import io.beacon.security.core.SecurityState;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class OccurrenceTest {
  @TempDir Path output;
  private final Map<String, String> previous = new HashMap<>();
  private final AtomicLong clock = new AtomicLong(1000000);

  @BeforeEach
  void configure() {
    for (String key :
        new String[] {
          "enabled",
          "output",
          "local-output.enabled",
          "findings.sample.seconds",
          "findings.max",
          "findings.max.bytes"
        }) {
      previous.put("beacon.security." + key, System.getProperty("beacon.security." + key));
    }
    System.setProperty("beacon.security.enabled", "true");
    System.setProperty("beacon.security.local-output.enabled", "true");
    System.setProperty("beacon.security.output", output.toString());
    System.setProperty("beacon.security.findings.sample.seconds", "300");
  }

  @AfterEach
  void restore() {
    previous.forEach(
        (key, value) -> {
          if (value == null) {
            System.clearProperty(key);
          } else {
            System.setProperty(key, value);
          }
        });
  }

  @Test
  void everyRequestHasAnOccurrenceWhileEvidenceIsSampled() {
    RuntimeLedger ledger = new RuntimeLedger(clock::get);
    List<Map<String, Object>> events = new ArrayList<>();
    for (int i = 1; i <= 3; i++) {
      events.add(emit(ledger, i, AttackEvidence.none("sql_data_only"), "fixture:sql", ""));
    }
    assertThat(events)
        .extracting(e -> e.get("finding_id"))
        .containsOnly(events.get(0).get("finding_id"));
    assertThat(events).extracting(e -> e.get("occurrence_id")).doesNotHaveDuplicates();
    assertThat(events)
        .extracting(e -> e.get("trace_id"))
        .containsExactly(trace(1), trace(2), trace(3));
    assertThat(events)
        .extracting(e -> e.get("evidence_sampled"))
        .containsExactly(true, false, false);
    assertThat(events)
        .allSatisfy(event -> assertThat(event).doesNotContainKey("occurrences_total"));
    assertThat(events.get(1))
        .containsEntry("truncated", false)
        .containsEntry("evidence_sample_reason", "interval");
    assertThat((List<?>) events.get(1).get("sources")).isEmpty();
    assertThat(events.get(1)).doesNotContainKey("evidence_id");
  }

  @Test
  void upgradesBypassSamplingAndRetainedEvidenceNeverRegresses() throws IOException {
    RuntimeLedger ledger = new RuntimeLedger(clock::get);
    emit(ledger, 1, AttackEvidence.none("sql_data_only"), "fixture:sql", "");
    Map<String, Object> attack =
        emit(ledger, 2, AttackEvidence.suspected("tainted_sql_structure"), "fixture:sql", "");
    assertThat(attack)
        .containsEntry("evidence_sampled", true)
        .containsEntry("evidence_sample_reason", "evidence_upgrade");
    clock.addAndGet(300000);
    Map<String, Object> ordinary =
        emit(ledger, 3, AttackEvidence.none("sql_data_only"), "fixture:sql", "");
    assertThat(ordinary).containsEntry("evidence_sampled", true);
    assertThat(((Map<?, ?>) ordinary.get("attack_evidence")).get("status"))
        .isEqualTo("no_evidence");
    ledger.tick(emptyMap(), true);
    Map<?, ?> snapshot =
        new ObjectMapper().readValue(output.resolve("findings.json").toFile(), Map.class);
    Map<?, ?> finding = (Map<?, ?>) ((List<?>) snapshot.get("findings")).get(0);
    assertThat(((Map<?, ?>) finding.get("representative")).get("trace_id")).isEqualTo(trace(2));
    assertThat(finding.get("last_trace_id")).isEqualTo(trace(3));
    Map<?, ?> counters = (Map<?, ?>) finding.get("attack_evidence_counts");
    assertThat(((Number) counters.get("unknown")).longValue()).isZero();
    assertThat(((Number) counters.get("no_evidence")).longValue()).isEqualTo(2L);
    assertThat(((Number) counters.get("suspected")).longValue()).isEqualTo(1L);
  }

  @Test
  void sameRequestUpgradesWithoutIncreasingOccurrenceCount() {
    RuntimeLedger ledger = new RuntimeLedger(clock::get);
    try (SecurityState state = new SecurityState()) {
      ledger.begin(state);
      String input = new String("guest");
      state.source(input, "http.parameter", "value", "fixture:source");
      Map<String, Object> first =
          evidence(state, input, AttackEvidence.none("sql_data_only"), "fixture:sql");
      state.pending(first);
      assertThat(evidence(state, input, AttackEvidence.none("sql_data_only"), "fixture:sql"))
          .isNull();
      Map<String, Object> uncertain =
          evidence(state, input, AttackEvidence.unknown("taint_imprecise"), "fixture:sql");
      state.pending(uncertain);
      assertThat(((Map<?, ?>) state.pending().get(0).get("attack_evidence")).get("status"))
          .isEqualTo("unknown");
      Map<String, Object> upgrade =
          evidence(state, input, AttackEvidence.suspected("tainted_sql_structure"), "fixture:sql");
      state.pending(upgrade);
      state.pending(first); // A slower caller must not replace the upgrade.
      assertThat(upgrade.get("occurrence_id")).isEqualTo(first.get("occurrence_id"));
      assertThat(state.pending()).hasSize(1);
      List<Map<String, Object>> events = ledger.end(state);
      assertThat(events).hasSize(1);
      assertThat(events.get(0)).doesNotContainKey("occurrences_total");
      assertThat(((Map<?, ?>) events.get(0).get("attack_evidence")).get("status"))
          .isEqualTo("suspected");
    }
  }

  @Test
  void intervalBoundaryAndRunChangesOnlyAffectEvidence() {
    RuntimeLedger ledger = new RuntimeLedger(clock::get);
    emit(ledger, 1, AttackEvidence.none("data"), "fixture:sql", "one");
    clock.addAndGet(299999);
    assertThat(emit(ledger, 2, AttackEvidence.none("data"), "fixture:sql", "one"))
        .containsEntry("evidence_sampled", false);
    clock.incrementAndGet();
    assertThat(emit(ledger, 3, AttackEvidence.none("data"), "fixture:sql", "one"))
        .containsEntry("evidence_sampled", true);
    assertThat(emit(ledger, 4, AttackEvidence.none("data"), "fixture:sql", "two"))
        .containsEntry("evidence_sampled", true);
  }

  @Test
  void absentTracesAndFullLedgerStillProduceOccurrences() {
    System.setProperty("beacon.security.findings.max", "1");
    System.setProperty("beacon.security.findings.max.bytes", "1");
    RuntimeLedger ledger = new RuntimeLedger(clock::get);
    Map<String, Object> first =
        emit(ledger, 0, AttackEvidence.unknown("missing_policy"), "fixture:first", "");
    assertThat(first).containsEntry("trace_id", "");
    Map<String, Object> second =
        emit(ledger, 0, AttackEvidence.unknown("missing_policy"), "fixture:second", "");
    assertThat(second)
        .containsEntry("evidence_sample_reason", "finding_capacity")
        .containsEntry("evidence_sampled", false)
        .doesNotContainKey("occurrences_total");
    assertThat(second.get("occurrence_id")).isNotNull().isNotEqualTo(first.get("occurrence_id"));
  }

  @Test
  void concurrentRequestsHaveIndependentIdsAndConsistentCounts() {
    RuntimeLedger ledger = new RuntimeLedger(clock::get);
    List<CompletableFuture<Map<String, Object>>> tasks = new ArrayList<>();
    for (int i = 1; i <= 32; i++) {
      int index = i;
      tasks.add(
          CompletableFuture.supplyAsync(
              () -> emit(ledger, index, AttackEvidence.none("data"), "fixture:sql", "")));
    }
    List<Map<String, Object>> events = new ArrayList<>();
    tasks.forEach(task -> events.add(task.join()));
    assertThat(events).extracting(e -> e.get("occurrence_id")).doesNotHaveDuplicates();
    assertThat(events).extracting(e -> e.get("trace_id")).doesNotHaveDuplicates();
    assertThat(events.stream().filter(e -> Boolean.TRUE.equals(e.get("evidence_sampled"))).count())
        .isEqualTo(1);
  }

  @Test
  void productionSamplingDoesNotRetainLocalRepresentativeEvidence() {
    System.setProperty("beacon.security.local-output.enabled", "false");
    RuntimeLedger ledger = new RuntimeLedger(clock::get);
    assertThat(emit(ledger, 1, AttackEvidence.none("data"), "fixture:sql", ""))
        .containsEntry("evidence_sampled", true);
    assertThat(emit(ledger, 2, AttackEvidence.none("data"), "fixture:sql", ""))
        .containsEntry("evidence_sampled", false);
    ledger.tick(emptyMap(), true);
    Map<?, ?> retention = (Map<?, ?>) ledger.health(emptyMap()).get("retention");
    assertThat(retention.get("representative_bytes_upper_bound")).isEqualTo(0L);
    assertThat(Files.exists(output.resolve("findings.json"))).isFalse();
  }

  private static String trace(int index) {
    return index == 0 ? "" : String.format(Locale.ROOT, "%032x", index);
  }

  private static Map<String, Object> emit(
      RuntimeLedger ledger, int index, AttackEvidence evidence, String site, String run) {
    try (SecurityState state = new SecurityState()) {
      ledger.begin(state);
      state.traceId = trace(index);
      state.serverSpanId = index == 0 ? "" : "1111111111111111";
      state.run = new HashMap<>();
      state.run.put("run_id", run);
      String input = new String("guest");
      state.source(input, "http.parameter", "value", "fixture:source");
      state.pending(evidence(state, input, evidence, site));
      return ledger.end(state).get(0);
    }
  }

  private static Map<String, Object> evidence(
      SecurityState state, String input, AttackEvidence evidence, String site) {
    return state.evidence(
        "sql_injection",
        "sql_template",
        "Statement.executeQuery",
        site,
        state.marks(input),
        "",
        evidence);
  }
}

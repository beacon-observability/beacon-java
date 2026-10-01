/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.beacon.security.exporter;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Collections.emptyMap;
import static java.util.Collections.singletonList;
import static java.util.concurrent.TimeUnit.MILLISECONDS;
import static java.util.concurrent.TimeUnit.SECONDS;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.beacon.security.core.Events;
import io.beacon.security.core.Identity;
import io.beacon.security.core.SecurityState;
import java.nio.ByteBuffer;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeoutException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Behavioral checks for the local inspection contract written by RuntimeLedger. */
class RuntimeLedgerBehaviorTest {
  private static final String[] SETTINGS = {
    "beacon.security.enabled", "beacon.security.output", "beacon.security.control.file",
    "beacon.security.findings.sample.seconds", "beacon.security.local-output.enabled",
        "beacon.security.runs.max.bytes"
  };

  private final Map<String, String> previousSettings = new HashMap<>();
  private final ObjectMapper json = new ObjectMapper();

  @BeforeEach
  void captureSettings() {
    for (String key : SETTINGS) previousSettings.put(key, System.getProperty(key));
    System.setProperty("beacon.security.enabled", "true");
    System.setProperty("beacon.security.local-output.enabled", "true");
  }

  @AfterEach
  void restoreSettings() {
    for (String key : SETTINGS) {
      String value = previousSettings.get(key);
      if (value == null) System.clearProperty(key);
      else System.setProperty(key, value);
    }
  }

  @Test
  void healthSeparatesTrafficSourceAndSinkStates(@TempDir Path temp) throws Exception {
    RuntimeLedger noTraffic = ledger(temp.resolve("no-traffic"));
    assertEquals("no_traffic", noTraffic.health(emptyMap()).get("status"));

    System.setProperty("beacon.security.enabled", "false");
    RuntimeLedger disabled = ledger(temp.resolve("disabled"));
    assertEquals("disabled", disabled.health(emptyMap()).get("status"));
    System.setProperty("beacon.security.enabled", "true");

    RuntimeLedger sourceOnly = ledger(temp.resolve("source-only"));
    SecurityState sourceState = new SecurityState();
    sourceState.source(new String("health-source"), "http.parameter", "value", "fixture:health");
    sourceOnly.begin(sourceState);
    sourceOnly.end(sourceState);
    assertEquals("no_sink_observed", sourceOnly.health(emptyMap()).get("status"));

    RuntimeLedger sinkOnly = ledger(temp.resolve("sink-only"));
    SecurityState sinkState = new SecurityState();
    sinkState.sink("sql_injection", "fixture:health-sink");
    sinkOnly.begin(sinkState);
    sinkOnly.end(sinkState);
    assertEquals("no_source_observed", sinkOnly.health(emptyMap()).get("status"));

    RuntimeLedger observed = ledger(temp.resolve("observed"));
    SecurityState observedState = stateWithEvidence("health-trace", "fixture:health-observed");
    observed.begin(observedState);
    observed.end(observedState);
    assertEquals("observed", observed.health(emptyMap()).get("status"));
  }

  @Test
  void stableFindingIsSampledOnceAndAggregatesLaterOccurrences(@TempDir Path temp)
      throws Exception {
    System.setProperty("beacon.security.findings.sample.seconds", "300");
    Path output = temp.resolve("ledger");
    Path control = output.resolve("control.json");
    System.setProperty("beacon.security.control.file", control.toString());
    RuntimeLedger ledger = ledger(output);
    writeControl(
        control,
        map(
            "revision",
            "request-shape",
            "paused",
            false,
            "run",
            run("run-request-shape", "case-request-shape")));
    ledger.tick(emptyMap(), ignored -> {}, true);

    SecurityState first = stateWithEvidence("trace-first", "fixture:aggregate");
    Map<String, Object> expectedRequest = requestShape(first);
    ledger.begin(first);
    List<Map<String, Object>> firstSample = ledger.end(first);

    SecurityState second = stateWithEvidence("trace-second", "fixture:aggregate");
    requestShape(second);
    ledger.begin(second);
    List<Map<String, Object>> secondSample = ledger.end(second);

    assertEquals(1, firstSample.size(), "the first occurrence is the representative sample");
    assertEquals(expectedRequest, firstSample.get(0).get("request"));
    assertTrue(secondSample.isEmpty(), "the same run does not emit another full evidence sample");
    assertEquals(firstSample.get(0).get("finding_id"), secondFindingId(second));

    ledger.tick(emptyMap(), ignored -> {}, true);
    Map<?, ?> snapshot = read(output.resolve("findings.json"));
    List<?> findings = (List<?>) snapshot.get("findings");
    assertEquals(1, findings.size());
    Map<?, ?> finding = (Map<?, ?>) findings.get(0);
    assertEquals(firstSample.get(0).get("finding_id"), finding.get("finding_id"));
    assertEquals(2L, ((Number) finding.get("occurrences")).longValue());
    assertEquals("candidate_risk", finding.get("assessment"));
    assertEquals("unvalidated", finding.get("validation"));
    assertFalse("confirmed".equals(finding.get("assessment")));
    assertEquals(expectedRequest, finding.get("request"));
    assertEquals(
        expectedRequest,
        runFrom(output.resolve("runs.json"), "run-request-shape").get("last_request"));
  }

  @Test
  void controlRevisionPausesThenResumesCollection(@TempDir Path temp) throws Exception {
    Path output = temp.resolve("ledger");
    Path control = output.resolve("control.json");
    System.setProperty("beacon.security.control.file", control.toString());
    RuntimeLedger ledger = ledger(output);

    writeControl(control, map("revision", "pause-revision", "paused", true));
    ledger.tick(emptyMap(), ignored -> {}, true);
    assertTrue(ledger.paused());
    assertEquals("paused", ledger.health(emptyMap()).get("status"));

    SecurityState pausedState = stateWithEvidence("trace-paused", "fixture:pause");
    ledger.begin(pausedState);
    assertFalse(pausedState.collectionEnabled);
    assertEquals("paused", pausedState.collectionStatus);
    ledger.end(pausedState);

    writeControl(
        control,
        map(
            "revision",
            "resume-revision",
            "paused",
            false,
            "run",
            run("run-resumed", "case-resume")));
    ledger.tick(emptyMap(), ignored -> {}, true);
    assertFalse(ledger.paused());
    SecurityState resumedState = stateWithEvidence("trace-resumed", "fixture:resume");
    ledger.begin(resumedState);
    assertTrue(resumedState.collectionEnabled);
    assertEquals("run-resumed", resumedState.run.get("run_id"));
    ledger.end(resumedState);
    ledger.tick(emptyMap(), ignored -> {}, true);

    Map<?, ?> runs = read(output.resolve("runs.json"));
    List<?> records = (List<?>) runs.get("runs");
    assertEquals(1, records.size());
    assertEquals("run-resumed", ((Map<?, ?>) records.get(0)).get("run_id"));
    assertEquals("case-resume", ((Map<?, ?>) records.get(0)).get("case_id"));
  }

  @Test
  void exceptionScopeNeedsReasonAndOnlyActiveExpiryChangesTriage(@TempDir Path temp)
      throws Exception {
    Path output = temp.resolve("ledger");
    Path control = output.resolve("control.json");
    System.setProperty("beacon.security.control.file", control.toString());
    RuntimeLedger ledger = ledger(output);

    SecurityState first = stateWithEvidence("trace-exception-first", "fixture:exception");
    ledger.begin(first);
    ledger.end(first);
    String findingId = String.valueOf(first.pending().get(0).get("finding_id"));

    Map<String, Object> activeException =
        map(
            "scope",
            map("application_id", Identity.applicationId(), "finding_id", findingId),
            "decision",
            "accepted_risk",
            "reason",
            "approved test fixture",
            "expires_at",
            Instant.now().plusSeconds(300).toString());
    writeControl(
        control, map("revision", "exception-active", "exceptions", singletonList(activeException)));
    ledger.tick(emptyMap(), ignored -> {}, true);
    ledger.tick(emptyMap(), ignored -> {}, true);
    Map<?, ?> active = findingFrom(output.resolve("findings.json"), findingId);
    assertEquals("accepted_risk", ((Map<?, ?>) active.get("triage")).get("decision"));
    assertEquals("approved test fixture", ((Map<?, ?>) active.get("triage")).get("reason"));

    Map<String, Object> expired =
        map(
            "scope",
            map("application_id", Identity.applicationId(), "finding_id", findingId),
            "decision",
            "false_positive",
            "reason",
            "expired test fixture",
            "expires_at",
            Instant.now().minusSeconds(1).toString());
    writeControl(
        control, map("revision", "exception-expired", "exceptions", singletonList(expired)));
    ledger.tick(emptyMap(), ignored -> {}, true);
    Map<?, ?> afterExpiry = findingFrom(output.resolve("findings.json"), findingId);
    assertEquals("unreviewed", ((Map<?, ?>) afterExpiry.get("triage")).get("decision"));

    Map<String, Object> missingReason =
        map(
            "scope",
            map("application_id", Identity.applicationId(), "finding_id", findingId),
            "decision",
            "accepted_risk",
            "expires_at",
            Instant.now().plusSeconds(300).toString());
    writeControl(
        control, map("revision", "exception-invalid", "exceptions", singletonList(missingReason)));
    ledger.tick(emptyMap(), ignored -> {}, true);
    Map<?, ?> invalidHealth = ledger.health(emptyMap());
    assertTrue(
        String.valueOf(invalidHealth.get("control_error")).contains("exception_reason_required"));
  }

  @Test
  void runKeepsObservedAndRiskSourceSignaturesSeparate(@TempDir Path temp) throws Exception {
    Path output = temp.resolve("ledger");
    Path control = output.resolve("control.json");
    System.setProperty("beacon.security.control.file", control.toString());
    RuntimeLedger ledger = ledger(output);

    writeControl(
        control,
        map(
            "revision",
            "source-baseline",
            "paused",
            false,
            "run",
            run("run-source-baseline", "case-source-boundary")));
    ledger.tick(emptyMap(), ignored -> {}, true);
    SecurityState baseline =
        stateWithSource("baseline-value", "http.request.parameter", "value[0]", true);
    ledger.begin(baseline);
    ledger.end(baseline);
    writeControl(control, map("revision", "source-baseline-close", "paused", false));
    ledger.tick(emptyMap(), ignored -> {}, true);

    writeControl(
        control,
        map(
            "revision",
            "source-candidate",
            "paused",
            false,
            "run",
            run("run-source-candidate", "case-source-boundary")));
    ledger.tick(emptyMap(), ignored -> {}, true);
    SecurityState candidate =
        stateWithSource("header-value", "http.request.header", "Accept", false);
    ledger.begin(candidate);
    ledger.end(candidate);
    writeControl(control, map("revision", "source-candidate-close", "paused", false));
    ledger.tick(emptyMap(), ignored -> {}, true);

    List<?> records = (List<?>) read(output.resolve("runs.json")).get("runs");
    Map<?, ?> baselineRun =
        records.stream()
            .map(Map.class::cast)
            .filter(value -> "run-source-baseline".equals(value.get("run_id")))
            .findFirst()
            .orElseThrow(() -> new AssertionError("missing baseline source-signature run"));
    Map<?, ?> candidateRun =
        records.stream()
            .map(Map.class::cast)
            .filter(value -> "run-source-candidate".equals(value.get("run_id")))
            .findFirst()
            .orElseThrow(() -> new AssertionError("missing candidate source-signature run"));
    assertEquals(1L, ((Number) baselineRun.get("observations")).longValue());
    assertEquals(
        1L,
        ((Number)
                ((Map<?, ?>) baselineRun.get("risk_source_signatures"))
                    .get("http.request.parameter|value[0]"))
            .longValue());
    assertEquals(
        1L,
        ((Number)
                ((Map<?, ?>) candidateRun.get("source_signatures"))
                    .get("http.request.header|Accept"))
            .longValue());
    assertTrue(((Map<?, ?>) candidateRun.get("risk_source_signatures")).isEmpty());
    assertEquals(0L, ((Number) candidateRun.get("observations")).longValue());
  }

  @Test
  void snapshotsStayOrderedAndIsolatedWhileRequestsContinue(@TempDir Path temp) throws Exception {
    Path control = temp.resolve("control.json");
    System.setProperty("beacon.security.control.file", control.toString());
    RuntimeLedger ledger = ledger(temp);
    writeControl(control, map("revision", "concurrent", "run", run("concurrent", "case")));
    ledger.tick(emptyMap(), event -> {}, true);
    SecurityState first = stateWithEvidence("first", "fixture:concurrent");
    ledger.begin(first);
    ledger.end(first);
    first.close();
    CountDownLatch oldCaptured = new CountDownLatch(1);
    CountDownLatch releaseOld = new CountDownLatch(1);
    CountDownLatch nextStarted = new CountDownLatch(1);
    CountDownLatch nextCaptured = new CountDownLatch(1);
    CountDownLatch releaseNext = new CountDownLatch(1);
    ExecutorService threads = Executors.newFixedThreadPool(2);
    try {
      Future<?> old =
          threads.submit(
              () ->
                  ledger.tick(
                      emptyMap(),
                      event -> {
                        oldCaptured.countDown();
                        awaitRelease(releaseOld);
                      },
                      true));
      assertTrue(oldCaptured.await(2, SECONDS));
      threads
          .submit(
              () -> {
                SecurityState second = stateWithEvidence("second", "fixture:concurrent");
                ledger.begin(second);
                ledger.end(second);
                second.close();
              })
          .get(2, SECONDS);
      Future<?> next =
          threads.submit(
              () -> {
                nextStarted.countDown();
                ledger.tick(
                    emptyMap(),
                    event -> {
                      nextCaptured.countDown();
                      awaitRelease(releaseNext);
                    },
                    true);
              });
      assertTrue(nextStarted.await(2, SECONDS));
      assertThrows(TimeoutException.class, () -> next.get(50, MILLISECONDS));
      releaseOld.countDown();
      old.get(5, SECONDS);
      assertTrue(nextCaptured.await(2, SECONDS));
      Map<?, ?> before = runFrom(temp.resolve("runs.json"), "concurrent");
      assertEquals(1L, ((Number) before.get("requests")).longValue());
      for (String field :
          new String[] {"finding_counts", "source_signatures", "risk_source_signatures"})
        assertTrue(
            ((Map<?, ?>) before.get(field))
                .values().stream().allMatch(count -> ((Number) count).longValue() == 1));
      releaseNext.countDown();
      next.get(5, SECONDS);
      Map<?, ?> after = runFrom(temp.resolve("runs.json"), "concurrent");
      assertEquals(2L, ((Number) after.get("requests")).longValue());
      for (String field :
          new String[] {"finding_counts", "source_signatures", "risk_source_signatures"})
        assertTrue(
            ((Map<?, ?>) after.get(field))
                .values().stream().allMatch(count -> ((Number) count).longValue() == 2));
      Map<?, ?> finding =
          (Map<?, ?>) ((List<?>) read(temp.resolve("findings.json")).get("findings")).get(0);
      assertEquals(2L, ((Number) finding.get("occurrences")).longValue());
    } finally {
      releaseOld.countDown();
      releaseNext.countDown();
      threads.shutdownNow();
      assertTrue(threads.awaitTermination(5, SECONDS));
    }
  }

  @Test
  void runCounterBudgetIsSharedAcrossRunsAndStillCountsExistingKeys(@TempDir Path temp)
      throws Exception {
    System.setProperty("beacon.security.runs.max.bytes", "256");
    Path control = temp.resolve("control.json");
    System.setProperty("beacon.security.control.file", control.toString());
    RuntimeLedger ledger = ledger(temp);
    writeControl(control, map("revision", "budget-one", "run", run("one", "case")));
    ledger.tick(emptyMap(), event -> {}, true);
    for (String name : new String[] {"a", "b", "a"}) {
      SecurityState state = stateWithSource("value", "http.request.parameter", name, false);
      ledger.begin(state);
      ledger.end(state);
      state.close();
    }
    writeControl(control, map("revision", "budget-two", "run", run("two", "case")));
    ledger.tick(emptyMap(), event -> {}, true);
    SecurityState state = stateWithSource("value", "http.request.parameter", "c", false);
    ledger.begin(state);
    ledger.end(state);
    state.close();
    ledger.tick(emptyMap(), event -> {}, true);
    Map<?, ?> first = runFrom(temp.resolve("runs.json"), "one");
    assertEquals(
        2L,
        ((Number) ((Map<?, ?>) first.get("source_signatures")).get("http.request.parameter|a"))
            .longValue());
    Map<?, ?> second = runFrom(temp.resolve("runs.json"), "two");
    assertTrue(((Map<?, ?>) second.get("source_signatures")).isEmpty());
    assertTrue(((Number) second.get("incomplete_requests")).longValue() > 0);
    Map<?, ?> health = read(temp.resolve("health.json"));
    assertEquals("incomplete", health.get("status"));
    Map<?, ?> retention = (Map<?, ?>) health.get("retention");
    assertTrue(((Number) retention.get("run_counter_bytes_upper_bound")).longValue() <= 256);
    assertEquals(256L, ((Number) retention.get("run_counter_bytes_max")).longValue());
  }

  @Test
  void controlPipeIsRejectedWithoutWaitingForAWriter(@TempDir Path temp) throws Exception {
    assumeTrue(System.getProperty("os.name").equals("Linux"));
    Path control = temp.resolve("control.json");
    assertEquals(0, new ProcessBuilder("mkfifo", control.toString()).start().waitFor());
    System.setProperty("beacon.security.control.file", control.toString());
    RuntimeLedger ledger = ledger(temp);
    ExecutorService thread = Executors.newSingleThreadExecutor();
    Future<?> tick = thread.submit(() -> ledger.tick(emptyMap(), event -> {}, true));
    try {
      tick.get(2, SECONDS);
      assertEquals(
          "control_regular_file_required", read(temp.resolve("health.json")).get("control_error"));
    } finally {
      if (!tick.isDone()) {
        try (SeekableByteChannel pipe =
            Files.newByteChannel(control, StandardOpenOption.READ, StandardOpenOption.WRITE)) {
          pipe.write(ByteBuffer.wrap("{}".getBytes(UTF_8)));
          Files.deleteIfExists(control);
        }
      }
      thread.shutdownNow();
      assertTrue(thread.awaitTermination(5, SECONDS));
    }
  }

  private static void awaitRelease(CountDownLatch release) {
    try {
      if (!release.await(5, SECONDS)) throw new AssertionError("snapshot not released");
    } catch (InterruptedException error) {
      Thread.currentThread().interrupt();
      throw new AssertionError(error);
    }
  }

  private static RuntimeLedger ledger(Path output) throws Exception {
    Files.createDirectories(output);
    System.setProperty("beacon.security.output", output.toString());
    return new RuntimeLedger();
  }

  private static SecurityState stateWithEvidence(String traceId, String location) {
    SecurityState state = new SecurityState();
    state.traceId = traceId;
    state.serverSpanId = "server-" + traceId;
    state.request.put("method", "GET");
    state.request.put("route", "/fixture/sql");
    state.request.put("status_code", 200);
    String source = new String("aggregate-value");
    state.source(source, "http.parameter", "value", "fixture:source");
    state.sink("sql_injection", location);
    Map<String, Object> event =
        state.evidence(
            "sql_injection",
            "query",
            "Statement.executeQuery",
            location,
            state.marks(source),
            "span-" + traceId);
    assertNotNull(event);
    state.pending(event);
    return state;
  }

  private static SecurityState stateWithSource(
      String value, String type, String name, boolean evidence) {
    SecurityState state = new SecurityState();
    state.traceId = "trace-" + name;
    state.serverSpanId = "server-" + name;
    state.request.put("method", "GET");
    state.request.put("route", "/fixture/source");
    state.request.put("status_code", 200);
    String source = new String(value);
    state.source(source, type, name, "fixture:source-signature");
    state.sink("sql_injection", "fixture:source-signature");
    if (evidence) {
      Map<String, Object> event =
          state.evidence(
              "sql_injection",
              "query",
              "Statement.executeQuery",
              "fixture:source-signature",
              state.marks(source),
              state.serverSpanId);
      assertNotNull(event);
      state.pending(event);
    }
    return state;
  }

  private static Map<String, Object> requestShape(SecurityState state) {
    state.request.put("method", "POST");
    state.request.put("route", "/fixture/request-shape");
    state.request.put("route_status", "matched");
    state.request.put("status_code", 201);
    state.request.put("started_at", "2026-09-08T04:00:00.123Z");
    state.request.put("ended_at", "2026-09-08T04:00:00.456Z");
    state.request.put("framework", "spring-webmvc");
    state.request.put("transport", "http");
    Map<String, Object> normalized = Events.request(state.request);
    assertEquals("", normalized.get("error_type"));
    return normalized;
  }

  private static String secondFindingId(SecurityState second) {
    return String.valueOf(second.pending().get(0).get("finding_id"));
  }

  private Map<?, ?> read(Path path) throws Exception {
    return json.readValue(Files.readAllBytes(path), Map.class);
  }

  private Map<?, ?> findingFrom(Path path, String findingId) throws Exception {
    List<?> findings = (List<?>) read(path).get("findings");
    for (Object value : findings) {
      Map<?, ?> finding = (Map<?, ?>) value;
      if (findingId.equals(finding.get("finding_id"))) return finding;
    }
    throw new AssertionError("missing finding " + findingId);
  }

  private Map<?, ?> runFrom(Path path, String runId) throws Exception {
    List<?> runs = (List<?>) read(path).get("runs");
    for (Object value : runs) {
      Map<?, ?> run = (Map<?, ?>) value;
      if (runId.equals(run.get("run_id"))) return run;
    }
    throw new AssertionError("missing run " + runId);
  }

  private static Map<String, Object> run(String runId, String caseId) {
    return map(
        "run_id",
        runId,
        "case_id",
        caseId,
        "rule",
        "sql_injection",
        "expires_at",
        Instant.now().plusSeconds(300).toString(),
        "conditions",
        map("suite", "runtime-ledger", "fixture", "sql", "expected_requests", 1));
  }

  private static void writeControl(Path path, Map<String, Object> value) throws Exception {
    Files.createDirectories(path.toAbsolutePath().getParent());
    Files.write(path, new ObjectMapper().writeValueAsBytes(value));
  }

  private static Map<String, Object> map(Object... values) {
    Map<String, Object> result = new LinkedHashMap<>();
    for (int i = 0; i < values.length; i += 2) result.put(String.valueOf(values[i]), values[i + 1]);
    return result;
  }
}

/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.beacon.security.exporter;

import static io.beacon.security.core.Values.map;
import static java.util.Arrays.asList;
import static java.util.Collections.emptyList;
import static java.util.Collections.emptyMap;
import static java.util.Collections.singletonMap;
import static java.util.logging.Level.WARNING;

import com.fasterxml.jackson.core.StreamReadConstraints;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.beacon.security.core.AttackEvidence;
import io.beacon.security.core.Events;
import io.beacon.security.core.Identity;
import io.beacon.security.core.SecurityState;
import io.beacon.security.core.Settings;
import io.beacon.security.core.StateCleanup;
import io.beacon.security.core.Values;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.LongSupplier;
import java.util.logging.Logger;

/**
 * Bounded process-local state. Snapshots are an inspection contract, not a durable backend
 * acknowledgement.
 */
public final class RuntimeLedger {
  private static final Logger logger = Logger.getLogger(RuntimeLedger.class.getName());

  private final ObjectMapper json = new ObjectMapper();
  private final LongSupplier clock;
  private final boolean configured = Settings.enabled("beacon.security.enabled", false);
  private final int maxActiveRequests = Settings.limit("beacon.security.max.active.requests", 256);
  private final int requestsPerSecond = Settings.limit("beacon.security.requests-per-second", 1000);
  private final int maxEvidenceBytes = Settings.limit("beacon.security.evidence.max.bytes", 65536);
  private final Map<String, Object> configuredRules = rules();
  private final String instrumentationProfile = profile();
  private final boolean localOutputEnabled =
      Settings.enabled("beacon.security.local-output.enabled", false);
  private final Path output =
      Paths.get(
              Settings.text(
                  "beacon.security.output", "./beacon-security-output/" + Identity.INSTANCE))
          .toAbsolutePath();
  private final Path control =
      Paths.get(
          Settings.text("beacon.security.control.file", output.resolve("control.json").toString()));
  private final Map<String, Map<String, Object>> findings = new LinkedHashMap<>();
  private final Map<String, Map<String, Object>> runs = new LinkedHashMap<>();
  private final Map<String, Long> counts = new LinkedHashMap<>();
  private final int maxFindings = Settings.limit("beacon.security.findings.max", 4096);
  private final int maxRuns = Settings.limit("beacon.security.runs.max", 256);
  private final long maxRunCounterBytes =
      Settings.limit("beacon.security.runs.max.bytes", 8 * 1024 * 1024);
  private long runCounterBytes;
  private final Set<Map<?, ?>> sharedRunCounters =
      Collections.newSetFromMap(new IdentityHashMap<Map<?, ?>, Boolean>());
  private final Object snapshotLock = new Object();
  private final AtomicBoolean shutdownUncertainty = new AtomicBoolean();
  private final long sampleMillis =
      Settings.limit("beacon.security.findings.sample.seconds", 300) * 1000L;
  private final long maxFindingBytes =
      Settings.limit("beacon.security.findings.max.bytes", 32 * 1024 * 1024);
  private long findingBytes;
  private final AtomicLong snapshotFailures = new AtomicLong();
  private volatile Map<String, Object> policy = emptyMap();
  private Map<String, List<TriageDecision>> exceptionIndex = emptyMap();
  private final Map<String, TriageDecision> triageCache = new LinkedHashMap<>();
  private volatile Map<String, Object> sbom = map("status", "initializing");
  private volatile Map<String, Object> lastDelivery = emptyMap();
  private long pauseGeneration;
  private volatile String controlError = "";
  private volatile String controlErrorRevision = "";
  private volatile String appliedRevision = "";
  private long snapshotAt;
  private long lastSnapshotFailureLog;
  private final long started = System.currentTimeMillis();
  private long active;
  private long completed;
  private long requestSecond;
  private int requestsThisSecond;

  public RuntimeLedger() {
    this(System::currentTimeMillis);
  }

  RuntimeLedger(LongSupplier clock) {
    this.clock = clock;
    json.getFactory()
        .setStreamReadConstraints(
            StreamReadConstraints.builder().maxNestingDepth(16).maxStringLength(4096).build());
  }

  boolean localOutputEnabled() {
    return localOutputEnabled;
  }

  public Path output() {
    return output;
  }

  public void shutdownIncomplete() {
    shutdownUncertainty.set(true);
  }

  public boolean enabled() {
    return configured && !paused();
  }

  public boolean paused() {
    return Boolean.TRUE.equals(policy.get("paused"));
  }

  public synchronized void count(String name) {
    counts.put(name, counts.getOrDefault(name, 0L) + 1);
  }

  public synchronized void count(String name, long amount) {
    counts.put(name, counts.getOrDefault(name, 0L) + amount);
  }

  public void sbom(Map<String, Object> value) {
    Map<String, Object> next = new LinkedHashMap<>();
    value.forEach(
        (key, item) -> {
          if (!key.equals("dependencies")
              && !key.equals("part_index")
              && !key.equals("part_count")) {
            next.put(key, item);
          }
        });
    sbom = next;
  }

  // The control-policy parser validates this erased Map before copying it into request state.
  public void begin(SecurityState state) {
    StateCleanup.reap();
    synchronized (this) {
      beginLocked(state);
    }
  }

  // Control policy maps are validated before publication.
  @SuppressWarnings("unchecked")
  private void beginLocked(SecurityState state) {
    String runId = "";
    Object run = policy.get("run");
    if (run instanceof Map && validUntil(((Map<?, ?>) run).get("expires_at"))) {
      state.run = new LinkedHashMap<>((Map<String, Object>) run);
      runId = String.valueOf(state.run.get("run_id"));
    }
    String registeredRun = runId;
    if (!state.registerRequestCleanup(() -> abandon(registeredRun))) {
      return;
    }
    active++;
    count("requests_started");
    state.collectionGeneration = pauseGeneration;
    long second = System.nanoTime() / 1000000000L;
    if (second != requestSecond) {
      requestSecond = second;
      requestsThisSecond = 0;
    }
    boolean requestBudget =
        active <= maxActiveRequests && ++requestsThisSecond <= requestsPerSecond;
    state.collectionEnabled = enabled() && requestBudget;
    state.collectionStatus =
        !configured
            ? "disabled"
            : paused() ? "paused" : !requestBudget ? "budget_skipped" : "enabled";
    if (!runId.isEmpty()) {
      Map<String, Object> record = runs.get(runId);
      if (record != null) {
        increment(record, "active_requests", 1);
      }
    }
  }

  public List<Map<String, Object>> end(SecurityState state) {
    Map<String, Object> request = Events.request(state.request);
    List<Map<String, Object>> prepared = new ArrayList<>();
    for (Map<String, Object> original : state.pending()) {
      Map<String, Object> event = Events.record(original);
      event.put("request", new LinkedHashMap<>(request));
      if (!state.run.isEmpty()) {
        event.put("run", new LinkedHashMap<>(state.run));
      }
      event.put("trace_availability", "not_guaranteed_by_trace_id");
      prepared.add(event);
    }
    synchronized (this) {
      return endLocked(state, request, prepared);
    }
  }

  private List<Map<String, Object>> endLocked(
      SecurityState state, Map<String, Object> request, List<Map<String, Object>> prepared) {
    if (!state.completeRequest()) {
      return emptyList();
    }
    active = Math.max(0, active - 1);
    completed++;
    count("requests_completed");
    count("sources", state.sourceCount());
    if (state.sourceCount() > 0) {
      count("requests_with_sources");
    }
    if (!state.sinkCounts().isEmpty()) {
      count("requests_with_sinks");
    }
    for (Map.Entry<String, Integer> sink : state.sinkCounts().entrySet()) {
      count("sink." + sink.getKey(), sink.getValue());
    }
    if (!state.collectionEnabled) {
      count("requests_" + state.collectionStatus);
    }
    boolean incomplete =
        state.truncated()
            || !state.gaps().isEmpty()
            || (state.collectionEnabled
                && (!enabled() || state.collectionGeneration != pauseGeneration));
    if (state.collectionEnabled && state.collectionGeneration != pauseGeneration) {
      state.gap("collection_paused_during_request");
    }
    if (incomplete) {
      count("requests_incomplete");
    }
    List<Map<String, Object>> result = new ArrayList<>();
    for (Map<String, Object> event : prepared) {
      event.put("collection_complete", !incomplete);
      if (incomplete) {
        event.put("truncated", state.truncated());
        event.put("coverage_gaps", state.gaps());
      }
      String id = String.valueOf(event.get("finding_id"));
      Map<String, Object> finding = findings.get(id);
      if (finding == null) {
        if (findings.size() >= maxFindings) {
          count("finding_capacity_dropped");
          event.put("evidence_sampled", false);
          event.put("evidence_sample_reason", "finding_capacity");
          omitEvidence(event);
          result.add(event);
          continue;
        }
        finding = map("last_sample_millis", 0L);
        if (localOutputEnabled) {
          finding.putAll(
              map(
                  "finding_id",
                  id,
                  "rule",
                  event.get("rule"),
                  "assessment",
                  event.get("assessment"),
                  "validation",
                  "unvalidated",
                  "sink",
                  event.get("sink"),
                  "first_seen",
                  event.get("observed_at"),
                  "attack_evidence_counts",
                  map("unknown", 0L, "no_evidence", 0L, "suspected", 0L),
                  "occurrences",
                  0L,
                  "last_sample_millis",
                  0L));
        }
        findings.put(id, finding);
      }
      if (localOutputEnabled) {
        increment(finding, "occurrences", 1);
        @SuppressWarnings("unchecked") // Created above with the three bounded status counters.
        Map<String, Object> evidenceCounts =
            (Map<String, Object>) finding.get("attack_evidence_counts");
        increment(evidenceCounts, AttackEvidence.status(event), 1);
        finding.put("last_seen", event.get("observed_at"));
        finding.put("last_trace_id", event.get("trace_id"));
        finding.put("last_occurrence_id", event.get("occurrence_id"));
        finding.put("last_run", new LinkedHashMap<>(state.run));
        finding.put("code", event.get("code"));
        finding.put("request", event.get("request"));
        finding.put("component", event.get("component"));
        finding.put("triage", triage(id));
      }
      if (localOutputEnabled) {
        event.put("triage", finding.get("triage"));
      }
      long now = clock.getAsLong();
      long lastSample = ((Number) finding.get("last_sample_millis")).longValue();
      String runId = String.valueOf(state.run.getOrDefault("run_id", ""));
      int rank = AttackEvidence.rank(event);
      int strongest = ((Number) finding.getOrDefault("strongest_evidence_rank", -1)).intValue();
      boolean upgrade = rank > strongest;
      boolean sample =
          upgrade
              || now - lastSample >= sampleMillis
              || !runId.equals(finding.get("sample_run_id"));
      event.put("evidence_sampled", sample);
      event.put(
          "evidence_sample_reason",
          upgrade ? "evidence_upgrade" : sample ? "interval_or_run" : "interval");
      if (upgrade) {
        finding.put("strongest_evidence_rank", rank);
        if (localOutputEnabled) {
          finding.put("strongest_attack_evidence", event.get("attack_evidence"));
          finding.put("assessment", event.get("assessment"));
        }
      }
      if (sample) {
        finding.put("last_sample_millis", now);
        finding.put("sample_run_id", runId);
        // Export this request's sample, but never replace stronger retained evidence with weaker
        // data.
        if (localOutputEnabled && rank >= strongest) {
          Map<String, Object> representative = new LinkedHashMap<>(event);
          long estimate = estimate(representative, 0);
          long previous = ((Number) finding.getOrDefault("representative_bytes", 0L)).longValue();
          if (estimate > maxEvidenceBytes || findingBytes - previous + estimate > maxFindingBytes) {
            omitEvidence(representative);
            representative.put("truncation_reason", "finding_snapshot_byte_budget");
            estimate = estimate(representative, 0);
            count("finding_sample_truncated");
          }
          if (findingBytes - previous + estimate <= maxFindingBytes) {
            findingBytes += estimate - previous;
            finding.put("representative_bytes", estimate);
            finding.put("representative", representative);
          } else {
            count("finding_sample_dropped");
          }
        }
      } else {
        count("representative_samples_suppressed");
        omitEvidence(event);
      }
      result.add(event);
    }
    Object runId = state.run.get("run_id");
    Map<String, Object> run = runId == null ? null : runs.get(String.valueOf(runId));
    if (run != null) {
      increment(run, "active_requests", -1);
      increment(run, "requests", 1);
      if (state.sourceCount() > 0) {
        increment(run, "source_requests", 1);
      }
      for (String signature : state.sourceSignatures()) {
        boundedIncrement(run, "source_signatures", signature);
      }
      String rule = String.valueOf(run.get("rule"));
      if (state.sinkCounts().getOrDefault(rule, 0) > 0) {
        increment(run, "sink_requests", 1);
      }
      if (incomplete || !state.collectionEnabled) {
        increment(run, "incomplete_requests", 1);
      }
      Object status = state.request.get("status_code");
      if (status instanceof Number && ((Number) status).intValue() >= 500) {
        increment(run, "error_requests", 1);
      }
      for (Map<String, Object> event : state.pending()) {
        if (rule.equals(event.get("rule"))) {
          increment(run, "observations", 1);
          for (Object item : (List<?>) event.get("sources")) {
            Map<?, ?> source = (Map<?, ?>) item;
            boundedIncrement(
                run, "risk_source_signatures", source.get("type") + "|" + source.get("name"));
          }
          boundedIncrement(run, "finding_counts", String.valueOf(event.get("finding_id")));
        }
      }
      if (!instrumentationProfile.equals(run.get("instrumentation_profile"))) {
        increment(run, "incomplete_requests", 1);
      }
      run.put("last_request", new LinkedHashMap<>(request));
      finishIfIdle(run);
    }
    return result;
  }

  private static void omitEvidence(Map<String, Object> event) {
    for (String field : new String[] {"propagation", "ranges", "sources", "stack"}) {
      event.put(field, emptyList());
    }
    event.put("evidence_sampled", false);
  }

  private synchronized void abandon(String runId) {
    active = Math.max(0, active - 1);
    count("requests_abandoned");
    count("requests_incomplete");
    Map<String, Object> run = runs.get(runId);
    if (run != null) {
      increment(run, "active_requests", -1);
      increment(run, "incomplete_requests", 1);
      finishIfIdle(run);
    }
  }

  private static long deliveryLoss(Map<String, Object> delivery) {
    long total =
        ((Number) delivery.getOrDefault("security_dropped", delivery.getOrDefault("dropped", 0L)))
            .longValue();
    Object counts = delivery.get("counters");
    if (counts instanceof Map) {
      for (Object item : ((Map<?, ?>) counts).entrySet()) {
        Map.Entry<?, ?> entry = (Map.Entry<?, ?>) item;
        String key = String.valueOf(entry.getKey());
        if (key.startsWith("beacon.security.")
            && (key.endsWith("failed") || key.endsWith("record_truncated"))) {
          total += ((Number) entry.getValue()).longValue();
        }
      }
    }
    return total;
  }

  public synchronized Map<String, Object> health(Map<String, Object> delivery) {
    String status =
        !configured
            ? "disabled"
            : paused()
                ? "paused"
                : completed == 0
                    ? active > 0 ? "in_flight" : "no_traffic"
                    : counts.getOrDefault("requests_incomplete", 0L) > 0
                            || counts.getOrDefault("requests_budget_skipped", 0L) > 0
                            || counts.getOrDefault("finding_capacity_dropped", 0L) > 0
                            || counts.getOrDefault("run_counter_capacity_dropped", 0L) > 0
                            || deliveryLoss(delivery) > 0
                        ? "incomplete"
                        : counts.getOrDefault("requests_with_sources", 0L) == 0
                            ? "no_source_observed"
                            : counts.getOrDefault("requests_with_sinks", 0L) == 0
                                ? "no_sink_observed"
                                : "observed";
    return map(
        "schema_version",
        Events.SCHEMA_VERSION,
        "source",
        "beacon_security",
        "event_name",
        "beacon.security.health",
        "updated_at",
        Events.now(),
        "started_at",
        Events.timestamp(started),
        "identity",
        Identity.context(),
        "version",
        Identity.VERSION,
        "instrumentation_profile",
        instrumentationProfile,
        "collection_status",
        !configured ? "disabled" : paused() ? "paused" : "enabled",
        "delivery_loss",
        deliveryLoss(delivery),
        "current_delivery_status",
        Boolean.TRUE.equals(delivery.get("security_loss_recent"))
            ? "loss_observed_in_last_60s"
            : "no_recent_loss_observed",
        "status",
        status,
        "configured",
        configured,
        "effective",
        enabled(),
        "active_requests",
        active,
        "counts",
        new LinkedHashMap<>(counts),
        "rule_status",
        configuredRules,
        "capabilities",
        asList(
            "http_server", "sql", "command", "http_client", "file", "modeled_string_propagation"),
        "coverage_semantics",
        "observed_counters_not_vulnerability_recall",
        "coverage_scope",
        "modeled_calls_only",
        "sbom",
        sbom,
        "delivery",
        delivery,
        "control_revision",
        appliedRevision,
        "control_error",
        controlError,
        "control_error_revision",
        controlErrorRevision,
        "snapshot_failures",
        snapshotFailures.get(),
        "retention",
        map(
            "findings_max",
            maxFindings,
            "runs_max",
            maxRuns,
            "run_counter_bytes_upper_bound",
            runCounterBytes,
            "run_counter_bytes_max",
            maxRunCounterBytes,
            "representative_bytes_upper_bound",
            findingBytes,
            "representative_bytes_max",
            maxFindingBytes),
        "pause_semantics",
        "collection_paused_existing_instrumentation_remains_loaded_restart_without_extension_to_unload");
  }

  public void tick(Map<String, Object> delivery, boolean force) {
    StateCleanup.reap();
    if (!localOutputEnabled) {
      return;
    }
    // Serialize the entire snapshot transaction without holding the monitor
    // used by request begin/end during serialization, callbacks or file I/O.
    synchronized (snapshotLock) {
      snapshot(delivery, force);
    }
  }

  private void snapshot(Map<String, Object> delivery, boolean force) {
    long now = System.currentTimeMillis();
    if (!force && now - snapshotAt < 1000) {
      return;
    }
    snapshotAt = now;
    lastDelivery = new LinkedHashMap<>(delivery);
    if (localOutputEnabled) {
      readControl();
    }
    List<Map<String, Object>> findingCopy = new ArrayList<>();
    List<Map<String, Object>> runCopy = new ArrayList<>();
    synchronized (this) {
      if (shutdownUncertainty.getAndSet(false)) {
        for (Map<String, Object> run : runs.values()) {
          if (((Number) run.getOrDefault("requests", 0L)).longValue() > 0) {
            increment(run, "delivery_loss", 1);
            increment(run, "incomplete_requests", 1);
          }
        }
      }
      for (Map<String, Object> run : runs.values()) {
        if (!validUntil(run.get("expires_at")) && "active".equals(run.get("status"))) {
          run.put("status", "draining");
          run.put("expired", true);
        }
        finishIfIdle(run);
      }
      for (Map<String, Object> finding : findings.values()) {
        finding.put("triage", triage(String.valueOf(finding.get("finding_id"))));
      }
      if (localOutputEnabled) {
        for (Map<String, Object> finding : findings.values()) {
          Map<String, Object> copy = new LinkedHashMap<>(finding);
          for (String key :
              new String[] {
                "dirty",
                "last_sample_millis",
                "sample_run_id",
                "representative_bytes",
                "strongest_evidence_rank"
              }) {
            copy.remove(key);
          }
          copy.put(
              "attack_evidence_counts",
              new LinkedHashMap<>((Map<?, ?>) finding.get("attack_evidence_counts")));
          findingCopy.add(copy);
        }
        for (Map<String, Object> run : runs.values()) {
          Map<String, Object> copy = new LinkedHashMap<>(run);
          for (String key :
              new String[] {"finding_counts", "source_signatures", "risk_source_signatures"}) {
            sharedRunCounters.add((Map<?, ?>) run.get(key));
          }
          copy.remove("loss_start");
          copy.remove("snapshot_failures_start");
          runCopy.add(copy);
        }
      }
    }
    if (!localOutputEnabled) {
      return;
    }
    try {
      write(
          output.resolve("findings.json"),
          json.writeValueAsBytes(envelope("findings", findingCopy)));
      write(output.resolve("runs.json"), json.writeValueAsBytes(envelope("runs", runCopy)));
      write(output.resolve("health.json"), json.writeValueAsBytes(health(delivery)));
    } catch (IOException error) {
      snapshotFailures.incrementAndGet();
      if (now - lastSnapshotFailureLog >= 30000) {
        lastSnapshotFailureLog = now;
        logger.log(
            WARNING,
            "[BeaconSecurity] local snapshot write failed: {0}",
            error.getClass().getSimpleName());
      }
    }
  }

  private static Map<String, Object> envelope(String key, Collection<?> values) {
    return map(
        "schema_version",
        Events.SCHEMA_VERSION,
        "source",
        "beacon_security",
        "updated_at",
        Events.now(),
        "identity",
        Identity.context(),
        key,
        new ArrayList<>(values));
  }

  // Jackson returns erased Maps; nested policy shapes are validated before the cast is used.
  @SuppressWarnings("unchecked")
  private void readControl() {
    if (!Files.exists(control)) {
      return;
    }
    String attemptedRevision = "unparsed";
    try {
      if (!Files.isRegularFile(control)) {
        throw new IOException("control_regular_file_required");
      }
      if (Files.size(control) > 256 * 1024) {
        throw new IOException("control_byte_limit");
      }
      Map<String, Object> next = json.readValue(control.toFile(), Map.class);
      String revision = String.valueOf(next.getOrDefault("revision", ""));
      attemptedRevision = revision;
      if (revision.isEmpty()) {
        throw new IOException("control_revision_required");
      }
      if (revision.equals(appliedRevision)) {
        return;
      }
      if (next.containsKey("paused") && !(next.get("paused") instanceof Boolean)) {
        throw new IOException("invalid_pause");
      }
      validateExceptions(next.get("exceptions"));
      Map<String, List<TriageDecision>> nextExceptions = indexExceptions(next.get("exceptions"));
      Object value = next.get("run");
      if (value != null) {
        if (!(value instanceof Map)) {
          throw new IOException("invalid_run");
        }
        Map<?, ?> run = (Map<?, ?>) value;
        for (String field : new String[] {"run_id", "case_id", "rule", "expires_at"}) {
          if (!(run.get(field) instanceof String) || ((String) run.get(field)).isEmpty()) {
            throw new IOException("missing_run_" + field);
          }
        }
        if (!validUntil(run.get("expires_at")) || !configuredRules.containsKey(run.get("rule"))) {
          throw new IOException("invalid_run_expiry_or_rule");
        }
        if (!(run.get("conditions") instanceof Map)) {
          throw new IOException("missing_run_conditions");
        }
        Map<?, ?> conditions = (Map<?, ?>) run.get("conditions");
        for (String field : new String[] {"suite", "fixture"}) {
          if (!(conditions.get(field) instanceof String)
              || ((String) conditions.get(field)).trim().isEmpty()) {
            throw new IOException("missing_condition_" + field);
          }
        }
        if (!(conditions.get("expected_requests") instanceof Number)
            || ((Number) conditions.get("expected_requests")).longValue() <= 0) {
          throw new IOException("expected_requests_required");
        }
      }
      synchronized (this) {
        Map<String, Object> newRun = (Map<String, Object>) value;
        String nextId = newRun == null ? "" : String.valueOf(newRun.get("run_id"));
        if (newRun != null
            && runs.containsKey(nextId)
            && !"active".equals(runs.get(nextId).get("status"))) {
          throw new IOException("run_id_already_closed");
        }
        if (newRun != null && !runs.containsKey(nextId) && runs.size() >= maxRuns) {
          throw new IOException("run_capacity_restart_or_archive");
        }
        for (Map<String, Object> old : runs.values()) {
          if ("active".equals(old.get("status")) && !nextId.equals(old.get("run_id"))) {
            old.put("status", "draining");
            finishIfIdle(old);
          }
        }
        if (newRun != null && !runs.containsKey(nextId)) {
          Map<String, Object> run = new LinkedHashMap<>(newRun);
          run.put("status", "active");
          run.put("started_at", Events.now());
          run.put("identity", Identity.context());
          run.put("rule_enabled", configuredRules.get(run.get("rule")));
          run.put("collection_enabled", configured && !Boolean.TRUE.equals(next.get("paused")));
          run.put("loss_start", lossTotal());
          run.put("snapshot_failures_start", snapshotFailures.get());
          run.put("instrumentation_profile", instrumentationProfile);
          run.put("finding_counts", new LinkedHashMap<String, Long>());
          run.put("source_signatures", new LinkedHashMap<String, Long>());
          run.put("risk_source_signatures", new LinkedHashMap<String, Long>());
          for (String key :
              new String[] {
                "requests",
                "source_requests",
                "sink_requests",
                "observations",
                "incomplete_requests",
                "error_requests",
                "active_requests"
              }) {
            run.put(key, 0L);
          }
          runs.put(nextId, run);
        }
        if (Boolean.TRUE.equals(policy.get("paused")) != Boolean.TRUE.equals(next.get("paused"))) {
          pauseGeneration++;
        }
        policy = next;
        exceptionIndex = nextExceptions;
        triageCache.clear();
        appliedRevision = revision;
      }
      controlError = "";
      controlErrorRevision = "";
    } catch (Exception error) {
      controlErrorRevision = attemptedRevision;
      controlError =
          Values.bounded(
              error.getMessage() == null ? error.getClass().getSimpleName() : error.getMessage(),
              256);
    }
  }

  private static long estimate(Object value, int depth) {
    if (value == null) {
      return 4;
    }
    if (depth > 16) {
      return 65536;
    }
    if (value instanceof String) {
      return ((String) value).length() * 6L + 2;
    }
    if (value instanceof Number || value instanceof Boolean) {
      return 32;
    }
    long bytes = 2;
    if (value instanceof Map) {
      for (Map.Entry<?, ?> entry : ((Map<?, ?>) value).entrySet()) {
        bytes += estimate(entry.getKey(), depth + 1) + estimate(entry.getValue(), depth + 1) + 2;
      }
    } else if (value instanceof Iterable) {
      for (Object entry : (Iterable<?>) value) {
        bytes += estimate(entry, depth + 1) + 1;
      }
    }
    return bytes;
  }

  private static String profile() {
    return Identity.digest(
        Identity.VERSION
            + "|"
            + rules()
            + "|"
            + Settings.text("beacon.security.instrumentation.exclude", "")
            + "|"
            + Settings.limit("beacon.security.max.objects", 4096)
            + "|"
            + Settings.limit("beacon.security.max.nodes", 8192)
            + "|"
            + Settings.limit("beacon.security.max.tracked.bytes", 1024 * 1024)
            + "|"
            + Settings.limit("beacon.security.max.process.tracked.bytes", 64 * 1024 * 1024));
  }

  private static Map<String, Object> rules() {
    Map<String, Object> result = new LinkedHashMap<>();
    for (String rule :
        new String[] {
          "sql_injection",
          "command_execution",
          "command_injection",
          "ssrf",
          "http_request_input",
          "path_traversal"
        }) {
      result.put(rule, Settings.enabled("beacon.security.rules." + rule + ".enabled", true));
    }
    return result;
  }

  private void finishIfIdle(Map<String, Object> run) {
    if ("draining".equals(run.get("status"))
        && ((Number) run.get("active_requests")).longValue() == 0) {
      run.put(
          "delivery_loss",
          Math.max(0, lossTotal() - ((Number) run.getOrDefault("loss_start", 0L)).longValue()));
      run.put(
          "snapshot_failures",
          Math.max(
              0,
              snapshotFailures.get()
                  - ((Number) run.getOrDefault("snapshot_failures_start", 0L)).longValue()));
      run.put("status", "closed");
      run.put("ended_at", Events.now());
    }
  }

  private long lossTotal() {
    return deliveryLoss(lastDelivery)
        + counts.getOrDefault("finding_capacity_dropped", 0L)
        + counts.getOrDefault("run_counter_capacity_dropped", 0L)
        + counts.getOrDefault("request_completion_errors", 0L);
  }

  private static void validateExceptions(Object value) throws IOException {
    if (value == null) {
      return;
    }
    if (!(value instanceof List) || ((List<?>) value).size() > 128) {
      throw new IOException("invalid_exceptions");
    }
    for (Object entry : (List<?>) value) {
      if (!(entry instanceof Map)) {
        throw new IOException("invalid_exception");
      }
      Map<?, ?> exception = (Map<?, ?>) entry;
      if (!(exception.get("scope") instanceof Map)) {
        throw new IOException("exception_scope_required");
      }
      Map<?, ?> scope = (Map<?, ?>) exception.get("scope");
      for (String field : new String[] {"finding_id"}) {
        if (!(scope.get(field) instanceof String) || ((String) scope.get(field)).isEmpty()) {
          throw new IOException("exception_scope_required");
        }
      }
      if (!(exception.get("reason") instanceof String)
          || ((String) exception.get("reason")).trim().isEmpty()) {
        throw new IOException("exception_reason_required");
      }
      if (!asList("accepted_risk", "false_positive").contains(exception.get("decision"))) {
        throw new IOException("invalid_exception_decision");
      }
      try {
        Instant.parse(String.valueOf(exception.get("expires_at")));
      } catch (DateTimeParseException error) {
        throw new IOException("exception_expiry_required", error);
      }
    }
  }

  private Map<String, Object> triage(String findingId) {
    Instant now = Instant.now();
    TriageDecision cached = triageCache.get(findingId);
    if (cached != null && cached.expires.isAfter(now)) {
      return cached.fields;
    }
    List<TriageDecision> candidates = exceptionIndex.get(findingId);
    if (candidates != null) {
      for (TriageDecision candidate : candidates) {
        if (candidate.expires.isAfter(now)) {
          triageCache.put(findingId, candidate);
          return candidate.fields;
        }
      }
    }
    TriageDecision unreviewed =
        new TriageDecision(Instant.MAX, singletonMap("decision", "unreviewed"));
    triageCache.put(findingId, unreviewed);
    return unreviewed.fields;
  }

  // Entries are checked by validateExceptions before this immutable index is built.
  @SuppressWarnings("unchecked")
  private static Map<String, List<TriageDecision>> indexExceptions(Object value) {
    Map<String, List<TriageDecision>> result = new LinkedHashMap<>();
    if (value instanceof List) {
      for (Object item : (List<?>) value) {
        Map<String, Object> entry = new LinkedHashMap<>((Map<String, Object>) item);
        Map<String, Object> scope = new LinkedHashMap<>((Map<String, Object>) entry.get("scope"));
        entry.put("scope", Collections.unmodifiableMap(scope));
        String key = String.valueOf(scope.get("finding_id"));
        result
            .computeIfAbsent(key, ignored -> new ArrayList<>())
            .add(
                new TriageDecision(
                    Instant.parse(String.valueOf(entry.get("expires_at"))),
                    Collections.unmodifiableMap(entry)));
      }
    }
    return result;
  }

  private static final class TriageDecision {
    final Instant expires;
    final Map<String, Object> fields;

    TriageDecision(Instant expires, Map<String, Object> fields) {
      this.expires = expires;
      this.fields = fields;
    }
  }

  private static boolean validUntil(Object expiry) {
    try {
      return Instant.parse(String.valueOf(expiry)).isAfter(Instant.now());
    } catch (DateTimeParseException error) {
      return false;
    }
  }

  // Run counter maps are created internally with Long values and never accept external entries.
  @SuppressWarnings("unchecked")
  private void boundedIncrement(Map<String, Object> run, String field, String key) {
    Map<String, Long> values = (Map<String, Long>) run.get(field);
    if (!values.containsKey(key)) {
      long bytes = 64L + key.length() * 2L;
      if (values.size() >= maxFindings || runCounterBytes + bytes > maxRunCounterBytes) {
        increment(run, "incomplete_requests", 1);
        count("run_counter_capacity_dropped");
        return;
      }
      runCounterBytes += bytes;
    }
    // Snapshots share immutable counter maps. Only the first update after a
    // snapshot copies one bounded table; unchanged historical runs never copy.
    if (sharedRunCounters.remove(values)) {
      values = new LinkedHashMap<>(values);
      run.put(field, values);
    }
    values.put(key, values.getOrDefault(key, 0L) + 1);
  }

  private static void increment(Map<String, Object> record, String key, long amount) {
    record.put(key, ((Number) record.getOrDefault(key, 0L)).longValue() + amount);
  }

  static void write(Path path, byte[] bytes) throws IOException {
    Files.createDirectories(path.toAbsolutePath().getParent());
    Path temporary =
        Files.createTempFile(path.toAbsolutePath().getParent(), ".beacon-security-", ".json");
    try {
      Files.write(temporary, bytes);
      Files.move(
          temporary, path, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
    } finally {
      Files.deleteIfExists(temporary);
    }
  }
}

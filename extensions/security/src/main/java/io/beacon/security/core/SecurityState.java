/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.beacon.security.core;

import static io.beacon.security.core.Values.map;
import static java.util.Collections.emptyList;
import static java.util.Collections.emptyMap;
import static java.util.Collections.singletonList;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.UUID;
import javax.annotation.Nullable;

public final class SecurityState implements AutoCloseable {
  private final RequestTracking objects = new RequestTracking();
  private final Set<String> gaps = new LinkedHashSet<>();
  private final Set<String> seen = new LinkedHashSet<>();
  private final Set<String> types = new LinkedHashSet<>();
  private final List<String> evidenceIds = new ArrayList<>();
  private final int maxObjects = Settings.limit("beacon.security.max.objects", 4096);
  private final int maxNodes = Settings.limit("beacon.security.max.nodes", 8192);
  private final int maxFindings = Settings.limit("beacon.security.max.findings", 32);
  private final int maxMarks = Settings.limit("beacon.security.max.marks-per-object", 64);
  private int nodes;
  private int sources;
  private final Set<String> sourceSignatures = new LinkedHashSet<>();

  public synchronized Set<String> sourceSignatures() {
    return new LinkedHashSet<>(sourceSignatures);
  }

  private final Map<String, Integer> sinks = new LinkedHashMap<>();
  private final Set<String> sinkSites = new LinkedHashSet<>();
  private final List<Map<String, Object>> pending = new ArrayList<>();
  public final long startedAt = System.currentTimeMillis();
  public final Map<String, Object> request = new LinkedHashMap<>();
  public Map<String, Object> run = emptyMap();
  public long collectionGeneration;
  public boolean collectionEnabled = true;
  public String collectionStatus = "enabled";

  public synchronized int sourceCount() {
    return sources;
  }

  public synchronized Map<String, Integer> sinkCounts() {
    return new LinkedHashMap<>(sinks);
  }

  public synchronized List<String> gaps() {
    return new ArrayList<>(gaps);
  }

  public synchronized void sink(String rule, String site) {
    if (sinkSites.size() >= maxNodes) {
      truncated = true;
      return;
    }
    if (sinkSites.add(rule + "|" + site)) {
      sinks.put(rule, sinks.getOrDefault(rule, 0) + 1);
    }
  }

  public synchronized void pending(Map<String, Object> event) {
    if (pending.size() < maxFindings) {
      pending.add(event);
    }
  }

  public synchronized List<Map<String, Object>> pending() {
    return new ArrayList<>(pending);
  }

  public synchronized List<String> findingIds() {
    Set<String> ids = new LinkedHashSet<>();
    for (Map<String, Object> event : pending) {
      ids.add(String.valueOf(event.get("finding_id")));
    }
    return new ArrayList<>(ids);
  }

  private boolean closed;
  private boolean truncated;
  public volatile String traceId = "";
  public volatile String serverSpanId = "";
  public volatile int traceFlags;

  public synchronized boolean active() {
    return !closed;
  }

  public synchronized boolean truncated() {
    return truncated;
  }

  public synchronized void gap(String reason) {
    if (gaps.size() < 32) {
      gaps.add(reason);
    }
  }

  public synchronized void container(Object object, String method, String name, String location) {
    if (closed || object == null) {
      return;
    }
    RequestTracking.Entry tracked = track(object);
    if (tracked != null) {
      update(tracked, tracked.marks, tracked.destination, new String[] {method, name, location});
    }
  }

  @Nullable
  public synchronized String[] container(Object object) {
    RequestTracking.Entry tracked = closed ? null : objects.get(object);
    return tracked == null ? null : tracked.container;
  }

  @Nullable
  public synchronized Map<String, Object> diagnostics() {
    if (!truncated && gaps.isEmpty() && collectionEnabled) {
      return null;
    }
    return map(
        "event_name",
        "beacon.security.collection.incomplete",
        "trace_id",
        traceId,
        "server_span_id",
        serverSpanId,
        "trace_flags",
        traceFlags,
        "truncated",
        truncated,
        "coverage_gaps",
        new ArrayList<>(gaps),
        "collection_status",
        collectionStatus,
        "counts",
        map(
            "objects",
            objects.size(),
            "nodes",
            nodes,
            "sources",
            sources,
            "findings",
            evidenceIds.size(),
            "retained_bytes",
            objects.bytes()));
  }

  public synchronized int trackedObjects() {
    return objects.size();
  }

  public synchronized long trackedBytes() {
    return objects.bytes();
  }

  public synchronized String destination(Object object) {
    RequestTracking.Entry tracked = closed ? null : objects.get(object);
    return tracked == null ? null : tracked.destination;
  }

  public synchronized void destination(Object object, String value) {
    if (closed || object == null) {
      return;
    }
    RequestTracking.Entry tracked = value == null ? objects.get(object) : track(object);
    if (tracked != null) {
      update(tracked, tracked.marks, value, tracked.container);
    }
  }

  public synchronized List<String> types() {
    return new ArrayList<>(types);
  }

  public synchronized List<String> evidenceIds() {
    return new ArrayList<>(evidenceIds);
  }

  public synchronized List<Mark> marks(Object object) {
    if (closed || object == null) {
      return emptyList();
    }
    RequestTracking.Entry result = objects.get(object);
    return result == null ? emptyList() : result.marks;
  }

  public synchronized void source(Object object, String type, String name, String location) {
    if (closed
        || !(object instanceof String)
        || ((String) object).isEmpty()
        || !marks(object).isEmpty()) {
      return;
    }
    if (nodes >= maxNodes) {
      truncated = true;
      return;
    }
    if (!reserveNode("source", location, 1024)) {
      return;
    }
    Map<String, Object> source =
        map(
            "id",
            "src-" + ++sources,
            "type",
            type,
            "name",
            Values.bounded(name, 256),
            "location",
            Values.bounded(location, 1024),
            "value_type",
            "string",
            "value_length",
            ((String) object).length());
    sourceSignatures.add(type + "|" + Values.bounded(name, 256));
    Mark.Node node = new Mark.Node(++nodes, null, source, "source", location);
    put(object, singletonList(new Mark(node, 0, Values.length(object), true)));
  }

  public synchronized List<Mark> step(
      List<Mark> inputs,
      String operation,
      String location,
      int shift,
      int clipStart,
      int clipEnd,
      boolean exact) {
    if (closed || inputs.isEmpty()) {
      return emptyList();
    }
    List<Mark> result = new ArrayList<>();
    for (Mark mark : inputs) {
      if (result.size() >= maxMarks || nodes >= maxNodes) {
        truncated = true;
        break;
      }
      int start = Math.max(mark.start, clipStart);
      int end = Math.min(mark.end, clipEnd);
      if (exact && start >= end) {
        continue;
      }
      if (!reserveNode(operation, location, 0)) {
        break;
      }
      Mark.Node node = new Mark.Node(++nodes, mark.node, mark.node.source, operation, location);
      result.add(
          new Mark(
              node,
              exact ? start + shift : 0,
              exact ? end + shift : Integer.MAX_VALUE,
              exact && mark.exact));
    }
    return result;
  }

  public void put(Object object, List<Mark> marks) {
    if (object == null) {
      return;
    }
    // StringBuffer.length acquires a business-owned monitor. Never acquire it
    // while holding request state: business code can acquire these locks in reverse.
    int length = marks.isEmpty() ? -1 : Values.length(object);
    synchronized (this) {
      if (closed) {
        return;
      }
      if (marks.isEmpty()) {
        RequestTracking.Entry tracked = objects.get(object);
        if (tracked != null) {
          update(tracked, emptyList(), tracked.destination, tracked.container);
        }
        return;
      }
      if (marks.size() > maxMarks) {
        truncated = true;
      }
      List<Mark> bounded = new ArrayList<>();
      for (Mark mark : marks.subList(0, Math.min(marks.size(), maxMarks))) {
        int end = length >= 0 ? Math.min(length, mark.end) : mark.end;
        if (mark.start < end) {
          bounded.add(new Mark(mark.node, mark.start, end, mark.exact));
        }
      }
      if (bounded.isEmpty()) {
        put(object, emptyList());
        return;
      }
      RequestTracking.Entry tracked = track(object);
      if (tracked != null) {
        update(
            tracked, Collections.unmodifiableList(bounded), tracked.destination, tracked.container);
      }
    }
  }

  private RequestTracking.Entry track(Object object) {
    RequestTracking.Entry tracked = objects.track(object, maxObjects);
    if (tracked == null) {
      truncated = true;
      gap("tracking_budget");
    }
    return tracked;
  }

  private void update(
      RequestTracking.Entry tracked, List<Mark> marks, String destination, String[] container) {
    if (!objects.update(tracked, marks, destination, container)) {
      objects.remove(tracked);
      truncated = true;
      gap("tracking_byte_budget");
    }
  }

  private boolean reserveNode(String operation, String location, long extra) {
    if (objects.reserve(
        128L
            + extra
            + 2L * (operation == null ? 0 : operation.length())
            + 2L * (location == null ? 0 : location.length()))) {
      return true;
    }
    truncated = true;
    gap("tracking_byte_budget");
    return false;
  }

  @Nullable
  public synchronized Map<String, Object> evidence(
      String rule,
      String role,
      String sink,
      String location,
      List<Mark> marks,
      String currentSpanId) {
    if (closed
        || marks.isEmpty()
        || !Settings.enabled("beacon.security.rules." + rule + ".enabled", true)) {
      return null;
    }
    if (marks.size() > maxMarks) {
      marks = marks.subList(0, maxMarks);
      truncated = true;
    }
    Map<String, Object> sourceMap = new LinkedHashMap<>();
    for (Mark mark : marks) {
      sourceMap.put((String) mark.node.source.get("id"), mark.node.source);
    }
    Map<String, Object> sinkFields = Events.sink(rule, role, sink, Values.bounded(location, 1024));
    String key =
        Events.fingerprint(
            Identity.applicationId(), "java", rule, sinkFields, sourceSignature(sourceMap));
    if (seen.contains(key)) {
      return null;
    }
    if (evidenceIds.size() >= maxFindings) {
      truncated = true;
      return null;
    }
    seen.add(key);
    String id = "ev-" + UUID.randomUUID();
    evidenceIds.add(id);
    types.add(rule);
    Map<Integer, Object> graph = new LinkedHashMap<>();
    boolean exact = true;
    for (Mark mark : marks) {
      exact &= mark.exact;
      Mark.Node node = mark.node;
      while (node != null && !graph.containsKey(node.id)) {
        if (graph.size() >= 128) {
          truncated = true;
          break;
        }
        graph.put(
            node.id,
            map(
                "id",
                node.id,
                "parent_id",
                node.parent == null ? null : node.parent.id,
                "source_id",
                node.source.get("id"),
                "operation",
                node.operation,
                "location",
                Values.bounded(node.location, 1024)));
        node = node.parent;
      }
    }
    List<Object> ranges = new ArrayList<>();
    for (Mark mark : marks) {
      ranges.add(
          map(
              "source_id",
              mark.node.source.get("id"),
              "start",
              mark.start,
              "end",
              mark.end == Integer.MAX_VALUE ? null : mark.end,
              "exact",
              mark.exact,
              "unit",
              "utf16_code_unit"));
    }
    return Events.record(
        map(
            "schema_version",
            1,
            "source",
            "beacon_security",
            "event_name",
            "beacon.security.finding",
            "evidence_id",
            id,
            "finding_id",
            key,
            "fingerprint_version",
            Events.FINGERPRINT_VERSION,
            "rule",
            rule,
            "assessment",
            candidate(rule, role) ? "candidate_risk" : "observation",
            "validation",
            "unvalidated",
            "severity",
            "unassigned",
            "confidence",
            exact ? "modeled_flow" : "conservative_flow",
            "observed_at",
            Events.now(),
            "execution_observation",
            "invocation_attempt",
            "precision",
            exact ? "exact" : "conservative",
            "trace_id",
            traceId,
            "server_span_id",
            serverSpanId,
            "current_span_id",
            currentSpanId,
            "trace_flags",
            traceFlags,
            "sources",
            new ArrayList<>(sourceMap.values()),
            "propagation",
            new ArrayList<>(graph.values()),
            "ranges",
            ranges,
            "sink",
            sinkFields,
            "truncated",
            truncated,
            "coverage",
            "modeled_calls_only",
            "coverage_gaps",
            new ArrayList<>(gaps)));
  }

  private static boolean candidate(String rule, String role) {
    return rule.equals("sql_injection")
        || rule.equals("command_injection")
        || role.equals("executable")
        || role.equals("destination_address");
  }

  private static Set<String> sourceSignature(Map<String, Object> sources) {
    Set<String> signatures = new TreeSet<>();
    for (Object entry : sources.values()) {
      Map<?, ?> source = (Map<?, ?>) entry;
      signatures.add(source.get("type") + "|" + source.get("name"));
    }
    return signatures;
  }

  @Override
  public synchronized void close() {
    closed = true;
    objects.clear();
    seen.clear();
    pending.clear();
    sinkSites.clear();
    sourceSignatures.clear();
  }
}

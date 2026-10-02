/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.beacon.security.core;

import static java.util.Collections.emptyList;

import java.lang.ref.ReferenceQueue;
import java.lang.ref.WeakReference;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

/** Access is serialized by the owning SecurityState monitor. */
final class RequestTracking {
  private static final AtomicLong PROCESS_BYTES = new AtomicLong();
  private final long maximum = Settings.limit("beacon.security.max.tracked.bytes", 1024 * 1024);
  private final long processMaximum =
      Settings.limit("beacon.security.max.process.tracked.bytes", 64 * 1024 * 1024);
  private final ReferenceQueue<Object> collected = new ReferenceQueue<>();
  private final Map<Key, Entry> entries = new HashMap<>();
  private final Lookup lookup = new Lookup();
  private long bytes;

  static class Key extends WeakReference<Object> {
    private final int hash;

    Key(Object value, ReferenceQueue<Object> queue) {
      super(value, queue);
      hash = System.identityHashCode(value);
    }

    @Override
    public int hashCode() {
      return hash;
    }

    @Override
    public boolean equals(Object other) {
      if (this == other) {
        return true;
      }
      Object value = get();
      return value != null && other instanceof Key && value == ((Key) other).get();
    }
  }

  private static final class Lookup {
    Object value;

    @Override
    public int hashCode() {
      return System.identityHashCode(value);
    }

    @Override
    public boolean equals(Object other) {
      return value != null && other instanceof Key && value == ((Key) other).get();
    }
  }

  static final class Entry extends Key {
    List<Mark> marks = emptyList();
    String destination;
    String[] container;
    final long baseBytes;
    long bytes;

    Entry(Object value, ReferenceQueue<Object> queue) {
      super(value, queue);
      baseBytes = 128 + (value instanceof String ? 2L * ((String) value).length() : 0);
      bytes = baseBytes;
    }
  }

  // HashMap.get accepts Object by design; Lookup deliberately mirrors Key's identity equality
  // without allocating a short-lived WeakReference for every lookup.
  @SuppressWarnings("CollectionIncompatibleType")
  Entry get(Object value) {
    // The owner serializes lookups. Never keep a strong carrier reference after one.
    lookup.value = value;
    try {
      return entries.get(lookup);
    } finally {
      lookup.value = null;
    }
  }

  Entry track(Object value, int maximumObjects) {
    prune();
    Entry entry = get(value);
    if (entry != null) {
      return entry;
    }
    if (entries.size() >= maximumObjects) {
      return null;
    }
    entry = new Entry(value, collected);
    if (!reserve(entry.bytes)) {
      return null;
    }
    entries.put(entry, entry);
    return entry;
  }

  boolean update(Entry entry, List<Mark> marks, String destination, String[] container) {
    long next = entry.baseBytes + marks.size() * 48L + stringBytes(destination);
    if (container != null) {
      for (String part : container) {
        next += stringBytes(part);
      }
    }
    if (!reserve(next - entry.bytes)) {
      return false;
    }
    entry.bytes = next;
    entry.marks = marks;
    entry.destination = destination;
    entry.container = container;
    if (marks.isEmpty() && destination == null && container == null) {
      remove(entry);
    }
    return true;
  }

  private static long stringBytes(String value) {
    return value == null ? 0 : 40L + 2L * value.length();
  }

  boolean reserve(long delta) {
    if (delta <= 0) {
      bytes += delta;
      PROCESS_BYTES.addAndGet(delta);
      return true;
    }
    if (delta > maximum - bytes) {
      return false;
    }
    long process;
    do {
      process = PROCESS_BYTES.get();
      if (delta > processMaximum - process) {
        return false;
      }
    } while (!PROCESS_BYTES.compareAndSet(process, process + delta));
    bytes += delta;
    return true;
  }

  void remove(Entry entry) {
    if (entries.remove(entry) != null) {
      bytes -= entry.bytes;
      PROCESS_BYTES.addAndGet(-entry.bytes);
    }
  }

  private void prune() {
    Entry entry;
    while ((entry = (Entry) collected.poll()) != null) {
      remove(entry);
    }
  }

  int size() {
    prune();
    return entries.size();
  }

  long bytes() {
    prune();
    return bytes;
  }

  void clear() {
    entries.clear();
    PROCESS_BYTES.addAndGet(-bytes);
    bytes = 0;
    while (collected.poll() != null) {}
  }
}

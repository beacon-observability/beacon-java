// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

import static java.util.Collections.emptyMap;

import io.beacon.security.core.SecurityState;
import io.beacon.security.exporter.RuntimeLedger;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicBoolean;

/** Standalone ledger contention probe; compile/run against the embedded security extension JAR. */
public class SecurityLedgerBenchmark {
  public static void main(String[] args) throws Exception {
    System.setProperty("beacon.security.enabled", "true");
    System.setProperty("beacon.security.local-output.enabled", "false");
    System.setProperty("beacon.security.requests-per-second", "10000000");
    System.setProperty(
        "beacon.security.output", Files.createTempDirectory("beacon-ledger-").toString());
    RuntimeLedger ledger = new RuntimeLedger();
    for (int i = 0; i < 4096; i++) {
      try (SecurityState state = new SecurityState()) {
        ledger.begin(state);
        String input = new String("fixture-value");
        state.source(input, "http.parameter", "value", "fixture:source");
        state.pending(
            state.evidence(
                "sql_injection",
                "query",
                "Statement.executeQuery",
                "fixture:" + i,
                state.marks(input),
                ""));
        ledger.end(state);
      }
    }
    for (int i = 0; i < 5; i++) ledger.tick(emptyMap(), event -> {}, true);
    ExecutorService workers = Executors.newFixedThreadPool(4);
    CountDownLatch ready = new CountDownLatch(4);
    CountDownLatch start = new CountDownLatch(1);
    AtomicBoolean pressure = new AtomicBoolean(true);
    AtomicBoolean snapshotting = new AtomicBoolean();
    List<Future<long[]>> tasks = new ArrayList<>();
    try {
      for (int worker = 0; worker < 4; worker++) {
        tasks.add(
            workers.submit(
                () -> {
                  ready.countDown();
                  start.await();
                  long[] waits = new long[100000];
                  int count = 0;
                  do {
                    try (SecurityState state = new SecurityState()) {
                      boolean overlap = snapshotting.get();
                      long before = System.nanoTime();
                      ledger.begin(state);
                      ledger.end(state);
                      if (overlap) waits[count++] = System.nanoTime() - before;
                    }
                  } while (pressure.get() && count < waits.length);
                  return Arrays.copyOf(waits, count);
                }));
      }
      ready.await();
      long[] snapshots = new long[100];
      start.countDown();
      for (int i = 0; i < snapshots.length; i++) {
        snapshotting.set(true);
        long before = System.nanoTime();
        ledger.tick(emptyMap(), event -> {}, true);
        snapshots[i] = System.nanoTime() - before;
        snapshotting.set(false);
        Thread.sleep(10);
      }
      pressure.set(false);
      List<long[]> samples = new ArrayList<>();
      int total = 0;
      for (Future<long[]> task : tasks) {
        long[] values = task.get();
        samples.add(values);
        total += values.length;
      }
      long[] waits = new long[total];
      int offset = 0;
      for (long[] sample : samples) {
        System.arraycopy(sample, 0, waits, offset, sample.length);
        offset += sample.length;
      }
      Arrays.sort(waits);
      Arrays.sort(snapshots);
      if (!Long.valueOf(0).equals(ledger.health(emptyMap()).get("active_requests")))
        throw new AssertionError("active lease leaked");
      System.out.println(
          "{\"findings\":4096,\"request_workers\":4,\"local_output\":false,\"snapshots\":100,\"snapshot_overlap_samples\":"
              + total
              + ",\"begin_end_p50_nanos\":"
              + waits[waits.length / 2]
              + ",\"begin_end_p99_nanos\":"
              + waits[(int) (waits.length * .99)]
              + ",\"begin_end_max_nanos\":"
              + waits[waits.length - 1]
              + ",\"snapshot_p50_nanos\":"
              + snapshots[50]
              + "}");
    } finally {
      pressure.set(false);
      start.countDown();
      workers.shutdownNow();
    }
  }
}

/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.instrumentation.profiling.internal;

import static java.util.concurrent.TimeUnit.SECONDS;
import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

class JfrRuntimeProfilingTest {
  @Test
  void closeExportsTheRemainderAfterAPeriodicExport() throws InterruptedException {
    Assumptions.assumeTrue(JfrSupport.isJfrAvailable());
    List<Instant> starts = new CopyOnWriteArrayList<>();
    List<Instant> ends = new CopyOnWriteArrayList<>();
    CountDownLatch periodic = new CountDownLatch(1);
    JfrRuntimeProfiling profiling =
        new JfrRuntimeProfiling(
            config(),
            snapshot -> {
              starts.add(snapshot.getStartTime());
              ends.add(snapshot.getEndTime());
              periodic.countDown();
            });
    try {
      profiling.start();
      assertThat(periodic.await(10, SECONDS)).isTrue();
    } finally {
      profiling.close();
    }
    assertThat(starts.size()).isGreaterThanOrEqualTo(2);
    for (int i = 1; i < starts.size(); i++) {
      assertThat(starts.get(i)).isEqualTo(ends.get(i - 1).plusNanos(1));
    }
    profiling.close();
    assertThat(starts).hasSameSizeAs(ends);
  }

  @Test
  void failedExportDoesNotAdvanceTheInterval() throws InterruptedException {
    Assumptions.assumeTrue(JfrSupport.isJfrAvailable());
    List<Instant> starts = new CopyOnWriteArrayList<>();
    AtomicBoolean fail = new AtomicBoolean(true);
    CountDownLatch failed = new CountDownLatch(1);
    JfrRuntimeProfiling profiling =
        new JfrRuntimeProfiling(
            config(),
            snapshot -> {
              starts.add(snapshot.getStartTime());
              if (fail.getAndSet(false)) {
                failed.countDown();
                throw new IllegalStateException("test export failure");
              }
            });
    try {
      profiling.start();
      assertThat(failed.await(10, SECONDS)).isTrue();
    } finally {
      profiling.close();
    }
    assertThat(starts.size()).isGreaterThanOrEqualTo(2);
    assertThat(starts.get(1)).isEqualTo(starts.get(0));
  }

  private static ProfilingConfig config() {
    return new ProfilingConfig(
        Duration.ofMillis(500),
        Duration.ZERO,
        Duration.ofMinutes(1),
        0,
        64,
        null,
        false,
        null,
        null);
  }
}

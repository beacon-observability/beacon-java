/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.instrumentation.profiling.internal;

import static java.util.concurrent.TimeUnit.SECONDS;
import static org.assertj.core.api.Assertions.assertThat;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

class ProfilingSchedulerTest {
  @Test
  void shutdownDeadlineDoesNotCloseResourcesUnderAnInFlightExport() throws InterruptedException {
    ProfilingScheduler scheduler = new ProfilingScheduler("profiling-shutdown-test");
    CountDownLatch exporting = new CountDownLatch(1);
    CountDownLatch release = new CountDownLatch(1);
    CountDownLatch finalized = new CountDownLatch(1);
    AtomicInteger phase = new AtomicInteger();
    scheduler.schedule(
        () -> {
          exporting.countDown();
          try {
            release.await();
            phase.set(1);
          } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
          }
        },
        0,
        SECONDS);
    try {
      assertThat(exporting.await(5, SECONDS)).isTrue();
      assertThat(
              scheduler.finish(
                  () -> {
                    phase.compareAndSet(1, 2);
                    finalized.countDown();
                  },
                  50))
          .isFalse();
      assertThat(phase.get()).isZero();
    } finally {
      release.countDown();
    }
    assertThat(finalized.await(5, SECONDS)).isTrue();
    assertThat(phase.get()).isEqualTo(2);
  }

  @Test
  void closeCancelsDelayedStartupButRunsFinalizer() {
    ProfilingScheduler scheduler = new ProfilingScheduler("profiling-delayed-test");
    AtomicInteger calls = new AtomicInteger();
    scheduler.schedule(() -> calls.addAndGet(100), 60, SECONDS);
    assertThat(scheduler.finish(calls::incrementAndGet, 5000)).isTrue();
    assertThat(calls.get()).isEqualTo(1);
  }
}

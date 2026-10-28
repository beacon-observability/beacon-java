/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.beacon.security.exporter;

import static io.beacon.security.core.Values.map;
import static java.util.Collections.emptyMap;
import static java.util.concurrent.TimeUnit.SECONDS;
import static org.assertj.core.api.Assertions.assertThat;

import io.beacon.security.core.SecurityState;
import java.util.AbstractMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.junit.jupiter.api.Test;
import org.junitpioneer.jupiter.SetSystemProperty;

class RuntimeLedgerConcurrencyTest {
  @Test
  @SetSystemProperty(key = "beacon.security.enabled", value = "true")
  void preparingOneRequestsEvidenceDoesNotBlockAnotherRequestAdmission() throws Exception {
    RuntimeLedger ledger = new RuntimeLedger();
    ExecutorService pool = Executors.newFixedThreadPool(2);
    CountDownLatch copying = new CountDownLatch(1);
    CountDownLatch release = new CountDownLatch(1);
    try (SecurityState first = new SecurityState();
        SecurityState second = new SecurityState()) {
      ledger.begin(first);
      Map<String, Object> event =
          new AbstractMap<String, Object>() {
            @Override
            public Set<Entry<String, Object>> entrySet() {
              copying.countDown();
              try {
                if (!release.await(10, SECONDS)) {
                  throw new AssertionError("copy release timed out");
                }
              } catch (InterruptedException failure) {
                Thread.currentThread().interrupt();
                throw new AssertionError(failure);
              }
              return map("event_name", "test", "occurrence_id", "evidence", "finding_id", "finding")
                  .entrySet();
            }
          };
      first.pending(event);
      Future<?> ending = pool.submit(() -> ledger.end(first));
      assertThat(copying.await(5, SECONDS)).isTrue();
      try {
        pool.submit(() -> ledger.begin(second)).get(2, SECONDS);
        assertThat(second.collectionEnabled).isTrue();
        ledger.end(second);
      } finally {
        release.countDown();
      }
      ending.get(5, SECONDS);
      assertThat(ledger.health(emptyMap()).get("active_requests")).isEqualTo(0L);
    } finally {
      release.countDown();
      pool.shutdownNow();
    }
  }
}

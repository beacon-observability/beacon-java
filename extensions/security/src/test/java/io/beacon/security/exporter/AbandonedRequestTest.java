/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.beacon.security.exporter;

import static java.util.Collections.emptyMap;
import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

import io.beacon.security.core.SecurityState;
import io.beacon.security.core.StateCleanup;
import java.lang.ref.WeakReference;
import java.lang.reflect.Field;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;
import org.junitpioneer.jupiter.SetSystemProperty;

class AbandonedRequestTest {
  @Test
  @SetSystemProperty(key = "beacon.security.enabled", value = "true")
  @SetSystemProperty(key = "beacon.security.max.active.requests", value = "1")
  void collectedStateReleasesBudgetAndAllowsTheNextRequest() throws Exception {
    RuntimeLedger ledger = new RuntimeLedger();
    long initialBytes = processBytes();
    WeakReference<SecurityState> abandoned = abandon(ledger);
    assertThat(processBytes()).isPositive();
    assertThat(ledger.health(emptyMap()).get("active_requests")).isEqualTo(1L);
    await()
        .atMost(Duration.ofSeconds(10))
        .untilAsserted(
            () -> {
              System.gc();
              StateCleanup.reap();
              assertThat(abandoned.get()).isNull();
              assertThat(ledger.health(emptyMap()).get("active_requests")).isEqualTo(0L);
              assertThat(processBytes()).isLessThanOrEqualTo(initialBytes);
            });
    try (SecurityState next = new SecurityState()) {
      ledger.begin(next);
      assertThat(next.collectionEnabled).isTrue();
      ledger.end(next);
      ledger.end(next);
    }
    assertThat(ledger.health(emptyMap()).get("active_requests")).isEqualTo(0L);
    Map<?, ?> counts = (Map<?, ?>) ledger.health(emptyMap()).get("counts");
    assertThat(counts.get("requests_abandoned")).isEqualTo(1L);
    assertThat(counts.get("requests_completed")).isEqualTo(1L);
  }

  @Test
  @SetSystemProperty(key = "beacon.security.enabled", value = "true")
  void explicitCloseWithoutEndAlsoReclaimsTheLeaseOnce() {
    RuntimeLedger ledger = new RuntimeLedger();
    SecurityState state = new SecurityState();
    ledger.begin(state);
    state.close();
    state.close();
    ledger.end(state);
    assertThat(ledger.health(emptyMap()).get("active_requests")).isEqualTo(0L);
    assertThat(state.trackedBytes()).isZero();
  }

  private static long processBytes() throws Exception {
    Field field =
        Class.forName("io.beacon.security.core.RequestTracking").getDeclaredField("PROCESS_BYTES");
    field.setAccessible(true);
    return ((AtomicLong) field.get(null)).get();
  }

  private static WeakReference<SecurityState> abandon(RuntimeLedger ledger) {
    SecurityState state = new SecurityState();
    state.source(new String("abandoned input"), "http.parameter", "input", "fixture:abandoned");
    ledger.begin(state);
    assertThat(state.trackedBytes()).isPositive();
    return new WeakReference<>(state);
  }
}

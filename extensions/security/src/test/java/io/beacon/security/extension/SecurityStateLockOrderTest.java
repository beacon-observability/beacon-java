/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.beacon.security.extension;

import static java.util.concurrent.TimeUnit.MILLISECONDS;
import static java.util.concurrent.TimeUnit.SECONDS;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.beacon.security.core.Call;
import io.beacon.security.core.Mark;
import io.beacon.security.core.Propagation;
import io.beacon.security.core.SecurityState;
import io.beacon.security.exporter.RuntimeLedger;
import java.lang.management.ManagementFactory;
import java.lang.management.ThreadInfo;
import java.lang.management.ThreadMXBean;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import org.junit.jupiter.api.Test;

/** Regression for the state -> StringBuffer lock ordering in propagation. */
class SecurityStateLockOrderTest {
  @Test
  void propagationDoesNotBlockStateAccessOrRequestCompletion() throws Exception {
    SecurityState state = new SecurityState();
    String source = new String("untrusted-buffer-value");
    state.source(source, "http.parameter", "value", "fixture:string-buffer-lock");
    StringBuffer buffer = new StringBuffer("prefix:");
    Call propagation =
        new Call(
            state,
            "java/lang/StringBuffer",
            "append",
            "(Ljava/lang/String;)Ljava/lang/StringBuffer;",
            buffer,
            new Object[] {source},
            "fixture:string-buffer-lock:propagation");

    RuntimeLedger ledger = new RuntimeLedger();
    ledger.begin(state);
    SecurityState nextState = new SecurityState();

    CountDownLatch businessHoldingBuffer = new CountDownLatch(1);
    CountDownLatch releaseBusiness = new CountDownLatch(1);
    ConcurrentLinkedQueue<Throwable> failures = new ConcurrentLinkedQueue<>();

    Thread business =
        daemon(
            "business-buffer-holder",
            () -> {
              try {
                synchronized (buffer) {
                  businessHoldingBuffer.countDown();
                  if (!releaseBusiness.await(3, SECONDS)) {
                    throw new AssertionError("timed out waiting to release StringBuffer");
                  }
                  buffer.append(source);
                  // This is the real request-side path that reads state while the
                  // application still owns the mutable business buffer.
                  new Call(
                      state,
                      "java/lang/StringBuffer",
                      "append",
                      "(Ljava/lang/String;)Ljava/lang/StringBuffer;",
                      buffer,
                      new Object[] {source},
                      "fixture:string-buffer-lock:business");
                }
              } catch (Throwable failure) {
                if (failure instanceof InterruptedException) {
                  Thread.currentThread().interrupt();
                }
                failures.add(failure);
              }
            });

    Thread propagationThread =
        daemon(
            "propagation-state-holder",
            () -> {
              try {
                if (!businessHoldingBuffer.await(3, SECONDS)) {
                  throw new AssertionError("business thread did not acquire StringBuffer");
                }
                Propagation.after(propagation, buffer);
              } catch (Throwable failure) {
                if (failure instanceof InterruptedException) {
                  Thread.currentThread().interrupt();
                }
                failures.add(failure);
              }
            });

    business.start();
    propagationThread.start();
    try {
      assertTrue(
          businessHoldingBuffer.await(3, SECONDS),
          "business thread must hold the real StringBuffer monitor");
      assertTrue(
          awaitBlockedOn(propagationThread, "java.lang.StringBuffer@", 3000L)
              || !propagationThread.isAlive(),
          "propagation should reach the StringBuffer length read");

      releaseBusiness.countDown();

      Thread stateReader =
          daemon(
              "state-reader",
              () -> {
                try {
                  assertFalse(state.marks(source).isEmpty());
                } catch (Throwable failure) {
                  failures.add(failure);
                }
              });
      Thread ledgerEnd =
          daemon(
              "ledger-end",
              () -> {
                try {
                  ledger.end(state);
                } catch (Throwable failure) {
                  failures.add(failure);
                }
              });

      stateReader.start();
      ledgerEnd.start();
      // On the buggy implementation end holds the ledger monitor while
      // waiting for state, so begin below also exposes the global amplification.
      awaitBlockedOn(ledgerEnd, SecurityState.class.getName() + "@", 1000L);
      Thread ledgerBegin =
          daemon(
              "ledger-begin",
              () -> {
                try {
                  ledger.begin(nextState);
                } catch (Throwable failure) {
                  failures.add(failure);
                }
              });
      ledgerBegin.start();

      join(business, 3000L);
      join(propagationThread, 3000L);
      join(stateReader, 3000L);
      join(ledgerEnd, 3000L);
      join(ledgerBegin, 3000L);

      assertFalse(business.isAlive(), "business path must not remain blocked on state");
      assertFalse(propagationThread.isAlive(), "propagation must complete");
      assertFalse(stateReader.isAlive(), "independent state access must complete");
      assertFalse(ledgerEnd.isAlive(), "request completion must complete");
      assertFalse(ledgerBegin.isAlive(), "a new request registration must complete");
      assertTrue(failures.isEmpty(), "worker failure: " + failures);

      List<Mark> marks = state.marks(buffer);
      assertEquals(1, marks.size(), "the propagated source marker must be retained");
      assertEquals("http.parameter", marks.get(0).node.source.get("type"));
      assertTrue(marks.get(0).start >= 0);
      assertTrue(marks.get(0).end <= buffer.length());
    } finally {
      releaseBusiness.countDown();
    }
  }

  private static Thread daemon(String name, Runnable task) {
    Thread thread = new Thread(task, name);
    thread.setDaemon(true);
    return thread;
  }

  private static void join(Thread thread, long timeoutMs) throws InterruptedException {
    thread.join(timeoutMs);
  }

  private static boolean awaitBlockedOn(Thread thread, String lockPrefix, long timeoutMs)
      throws InterruptedException {
    ThreadMXBean mx = ManagementFactory.getThreadMXBean();
    long deadline = System.nanoTime() + MILLISECONDS.toNanos(timeoutMs);
    while (System.nanoTime() < deadline) {
      ThreadInfo[] infos = mx.getThreadInfo(new long[] {thread.getId()}, true, true);
      ThreadInfo info = infos.length == 0 ? null : infos[0];
      if (info != null
          && info.getThreadState() == Thread.State.BLOCKED
          && info.getLockName() != null
          && info.getLockName().startsWith(lockPrefix)) {
        return true;
      }
      if (info == null || info.getThreadState() == Thread.State.TERMINATED) return false;
      Thread.sleep(10L);
    }
    return false;
  }
}

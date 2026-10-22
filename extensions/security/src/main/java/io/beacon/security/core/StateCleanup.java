/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.beacon.security.core;

import java.lang.ref.PhantomReference;
import java.lang.ref.ReferenceQueue;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

/** Java 8 compatible cleanup for our own request state, not a third-party carrier registry. */
public final class StateCleanup extends PhantomReference<SecurityState> implements Runnable {
  private static final ReferenceQueue<SecurityState> QUEUE = new ReferenceQueue<>();
  private static final Set<StateCleanup> REGISTRATIONS = ConcurrentHashMap.newKeySet();
  private final Runnable releaseBytes;
  private final AtomicReference<Runnable> releaseRequest = new AtomicReference<>();
  private final AtomicBoolean completed = new AtomicBoolean();
  private final AtomicBoolean cleaned = new AtomicBoolean();

  StateCleanup(SecurityState state, Runnable releaseBytes) {
    super(state, QUEUE);
    this.releaseBytes = releaseBytes;
    REGISTRATIONS.add(this);
  }

  boolean registerRequest(Runnable release) {
    return !completed.get() && releaseRequest.compareAndSet(null, release);
  }

  boolean completeRequest() {
    if (!completed.compareAndSet(false, true)) {
      return false;
    }
    releaseRequest.set(null);
    return true;
  }

  @Override
  public void run() {
    if (!cleaned.compareAndSet(false, true)) {
      return;
    }
    REGISTRATIONS.remove(this);
    clear();
    releaseBytes.run();
    Runnable release = releaseRequest.getAndSet(null);
    if (completed.compareAndSet(false, true) && release != null) {
      release.run();
    }
  }

  public static void reap() {
    StateCleanup registration;
    while ((registration = (StateCleanup) QUEUE.poll()) != null) {
      registration.run();
    }
  }
}

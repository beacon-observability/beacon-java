/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.instrumentation.profiling.internal;

import static java.util.concurrent.TimeUnit.MILLISECONDS;

import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;

final class ProfilingScheduler implements AutoCloseable {

  private final ScheduledThreadPoolExecutor executor;

  ProfilingScheduler(String threadName) {
    executor =
        new ScheduledThreadPoolExecutor(
            1,
            new ThreadFactory() {
              @Override
              public Thread newThread(Runnable runnable) {
                Thread thread = new Thread(runnable, threadName);
                thread.setDaemon(true);
                thread.setContextClassLoader(null);
                return thread;
              }
            });
    executor.setExecuteExistingDelayedTasksAfterShutdownPolicy(false);
    executor.setContinueExistingPeriodicTasksAfterShutdownPolicy(false);
  }

  void schedule(Runnable runnable, long delay, TimeUnit unit) {
    executor.schedule(runnable, delay, unit);
  }

  void scheduleAtFixedRate(Runnable runnable, long initialDelay, long period, TimeUnit unit) {
    executor.scheduleAtFixedRate(runnable, initialDelay, period, unit);
  }

  @Override
  public void close() {
    executor.shutdownNow();
  }

  boolean finish(Runnable finalExport, long timeoutMillis) {
    // The final export shares the worker with periodic exports. Shutdown cancels delayed/periodic
    // work, but this immediate task drains after any export that is already running.
    executor.execute(finalExport);
    executor.shutdown();
    try {
      return executor.awaitTermination(timeoutMillis, MILLISECONDS);
    } catch (InterruptedException interrupted) {
      Thread.currentThread().interrupt();
      return false;
    }
    // Do not close the recording on the caller thread when the deadline expires. The daemon worker
    // still owns its snapshot and will run finalExport once the in-flight exporter returns.
  }
}

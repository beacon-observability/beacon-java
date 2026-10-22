/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.instrumentation.profiling.internal;

import static java.util.concurrent.TimeUnit.MILLISECONDS;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;

final class ProfilingScheduler implements AutoCloseable {

  private final ScheduledThreadPoolExecutor executor;
  private final List<ScheduledFuture<?>> scheduledTasks = new ArrayList<>();

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
    // Java 8 also treats execute() tasks queued behind an active export as delayed work.
    // Retain the final task on shutdown; finish() explicitly cancels older scheduled work.
    executor.setExecuteExistingDelayedTasksAfterShutdownPolicy(true);
    executor.setContinueExistingPeriodicTasksAfterShutdownPolicy(false);
  }

  synchronized void schedule(Runnable runnable, long delay, TimeUnit unit) {
    scheduledTasks.add(executor.schedule(runnable, delay, unit));
  }

  synchronized void scheduleAtFixedRate(
      Runnable runnable, long initialDelay, long period, TimeUnit unit) {
    scheduledTasks.add(executor.scheduleAtFixedRate(runnable, initialDelay, period, unit));
  }

  @Override
  public void close() {
    executor.shutdownNow();
  }

  boolean finish(Runnable finalExport, long timeoutMillis) {
    // Serialize registration with cancellation and shutdown. cancel(false) prevents future runs
    // without interrupting an export already in progress; the final task shares that same worker.
    synchronized (this) {
      for (ScheduledFuture<?> task : scheduledTasks) {
        task.cancel(false);
      }
      scheduledTasks.clear();
      executor.execute(finalExport);
      executor.shutdown();
    }
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

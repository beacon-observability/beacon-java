/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.beacon.security.exporter;

import static io.beacon.security.core.Values.map;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.concurrent.TimeUnit.MILLISECONDS;
import static java.util.concurrent.TimeUnit.NANOSECONDS;
import static java.util.concurrent.TimeUnit.SECONDS;
import static java.util.logging.Level.WARNING;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.beacon.security.core.AttackEvidence;
import io.beacon.security.core.Events;
import io.beacon.security.core.Identity;
import io.beacon.security.core.Settings;
import io.opentelemetry.api.GlobalOpenTelemetry;
import io.opentelemetry.api.common.AttributeKey;
import io.opentelemetry.api.logs.Severity;
import io.opentelemetry.context.Context;
import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.LongSupplier;
import java.util.logging.Logger;
import javax.annotation.Nullable;

public final class EvidenceExporter implements AutoCloseable {
  private static final Logger logger = Logger.getLogger(EvidenceExporter.class.getName());

  private final ObjectMapper json = new ObjectMapper();
  private final LongSupplier nanoClock;
  private final ArrayBlockingQueue<Entry> queue =
      new ArrayBlockingQueue<>(Settings.limit("beacon.security.export.queue.size", 1024));
  private final ArrayBlockingQueue<Entry> sbomQueue =
      new ArrayBlockingQueue<>(Settings.limit("beacon.security.export.sbom.queue.size", 256));
  private final ArrayBlockingQueue<Entry> evidenceQueue =
      new ArrayBlockingQueue<>(Settings.limit("beacon.security.export.priority.queue.size", 128));
  private final AtomicLong lastSecurityLoss = new AtomicLong(Long.MIN_VALUE);
  private final RuntimeLedger ledger = new RuntimeLedger();
  private final ConcurrentHashMap<String, AtomicLong> counters = new ConcurrentHashMap<>();
  private final ScheduledExecutorService monitor =
      Executors.newSingleThreadScheduledExecutor(
          r -> {
            Thread thread = new Thread(r, "BeaconSecurity-local-output");
            thread.setDaemon(true);
            return thread;
          });
  private final Thread sbomWorker;
  @Nullable private final ScheduledFuture<?> monitoring;
  private final CountDownLatch shutdownComplete = new CountDownLatch(1);
  private final AtomicBoolean shutdownIncomplete = new AtomicBoolean();
  private boolean closing;
  private volatile long shutdownDeadline;
  private volatile long lastFileSuccess;
  private volatile long lastOtelCall;
  private final AtomicLong dropped = new AtomicLong();
  private final AtomicLong securityDropped = new AtomicLong();
  private final AtomicLong sbomDropped = new AtomicLong();
  private final int maxBytes = Settings.limit("beacon.security.evidence.max.bytes", 65536);
  private final long rotateBytes =
      Settings.limit("beacon.security.evidence.file.max.bytes", 10 * 1024 * 1024);
  private final int backups =
      Math.min(20, Settings.limit("beacon.security.evidence.file.backups", 3));
  private final Path file;
  private final Thread worker;
  private volatile boolean running = true;
  private BufferedWriter writer;
  private long fileBytes;
  private long lastError;

  public EvidenceExporter() {
    this(System::nanoTime);
  }

  EvidenceExporter(LongSupplier nanoClock) {
    this.nanoClock = nanoClock;
    String configured = Settings.text("beacon.security.evidence.file", "");
    file = configured.isEmpty() ? null : Paths.get(configured).toAbsolutePath();
    worker = new Thread(this::run, "BeaconSecurity-export");
    worker.setDaemon(true);
    worker.start();
    sbomWorker = new Thread(() -> runChannel(sbomQueue, "sbom"), "BeaconSecurity-sbom-export");
    sbomWorker.setDaemon(true);
    sbomWorker.start();
    monitoring =
        ledger.localOutputEnabled()
            ? monitor.scheduleWithFixedDelay(
                () -> {
                  try {
                    ledger.tick(delivery(), false);
                  } catch (Throwable error) {
                    logFailure(error);
                  }
                },
                0,
                1,
                SECONDS)
            : null;
  }

  public RuntimeLedger ledger() {
    return ledger;
  }

  public void emit(Map<String, Object> event, Context context, boolean evidence) {
    Object name = event.get("event_name");
    if (!"beacon.security.finding".equals(name) && !"beacon.security.sbom.inventory".equals(name)) {
      return;
    }
    String channel = "beacon.security.sbom.inventory".equals(name) ? "sbom" : "security";
    if (channel.equals("sbom")
        && (!(event.get("dependencies") instanceof List)
            || event.containsKey("error")
            || "error".equals(event.get("status")))) {
      return;
    }
    int priority = channel.equals("sbom") ? 0 : priority(event);
    ArrayBlockingQueue<Entry> target =
        channel.equals("sbom") ? sbomQueue : priority == 2 ? evidenceQueue : queue;
    if (!running) {
      loss(channel + ".closed");
      return;
    }
    if (!target.offer(new Entry(Events.record(event), context, evidence, priority))) {
      loss(channel + ".queue_full");
    } else {
      counter(channel + ".queued").incrementAndGet();
    }
  }

  public long dropped() {
    return dropped.get();
  }

  private AtomicLong counter(String name) {
    return counters.computeIfAbsent(name, key -> new AtomicLong());
  }

  private void loss(String reason) {
    dropped.incrementAndGet();
    boolean sbom = reason.startsWith("sbom.");
    if (!sbom) {
      lastSecurityLoss.set(nanoClock.getAsLong());
    }
    (sbom ? sbomDropped : securityDropped).incrementAndGet();
    counter(reason).incrementAndGet();
  }

  public Map<String, Object> delivery() {
    Map<String, Object> values = new TreeMap<>();
    counters.forEach((key, value) -> values.put(key, value.get()));
    return map(
        "counters",
        values,
        "dropped",
        dropped.get(),
        "security_dropped",
        securityDropped.get(),
        "sbom_dropped",
        sbomDropped.get(),
        "security_queue_depth",
        queue.size() + evidenceQueue.size(),
        "security_priority_queue_depth",
        evidenceQueue.size(),
        "loss_window_seconds",
        60,
        "security_loss_recent",
        lastSecurityLoss.get() != Long.MIN_VALUE
            && nanoClock.getAsLong() - lastSecurityLoss.get() < SECONDS.toNanos(60),
        "sbom_queue_depth",
        sbomQueue.size(),
        "last_file_write_at",
        lastFileSuccess == 0 ? null : Events.timestamp(lastFileSuccess),
        "last_otel_api_call_at",
        lastOtelCall == 0 ? null : Events.timestamp(lastOtelCall),
        "evidence_file",
        file == null ? "disabled" : file.toString(),
        "otel_logs_config",
        Settings.text("otel.logs.exporter", "agent_default"),
        "backend_acknowledgement",
        "unknown",
        "otel_semantics",
        "api_emit_is_not_export_or_backend_ack",
        "delivery_guarantee",
        "bounded_best_effort_no_agent_replay",
        "file_write_semantics",
        "flushed_not_fsynced");
  }

  private void run() {
    runChannel(queue, "security");
  }

  private void runChannel(ArrayBlockingQueue<Entry> channelQueue, String channel) {
    long second = 0;
    long bytes = 0;
    int events = 0;
    int normalEvents = 0;
    long normalBytes = 0;
    boolean security = channel.equals("security");
    int eventLimit =
        Settings.limit(
            "beacon.security.export." + channel + ".events-per-second",
            channel.equals("security") ? 100 : 200);
    long byteLimit =
        Settings.limit(
            "beacon.security.export." + channel + ".bytes-per-second",
            channel.equals("security") ? 524288 : 262144);
    while (running || !channelQueue.isEmpty() || (security && !evidenceQueue.isEmpty())) {
      try {
        Entry entry = security ? evidenceQueue.poll() : null;
        if (entry == null) {
          entry = channelQueue.poll(100, MILLISECONDS);
        }
        if (entry == null) {
          continue;
        }
        long now = nanoClock.getAsLong() / 1000000000L;
        if (now != second) {
          second = now;
          events = 0;
          bytes = 0;
          normalEvents = 0;
          normalBytes = 0;
        }
        Encoded encoded = encode(entry.event);
        if (encoded.truncated) {
          counter(channel + ".record_truncated").incrementAndGet();
        }
        int reservedEvents = security && eventLimit > 1 ? Math.max(1, eventLimit / 5) : 0;
        long reservedBytes = security ? byteLimit / 4 : 0;
        boolean normalBudget =
            security
                && entry.priority == 0
                && (normalEvents >= eventLimit - reservedEvents
                    || normalBytes + encoded.bytes.length > byteLimit - reservedBytes);
        if (normalBudget || events >= eventLimit || bytes + encoded.bytes.length > byteLimit) {
          if (!channel.equals("sbom") || encoded.bytes.length > byteLimit) {
            loss(channel + ".budget_exceeded");
            continue;
          }
          counter("sbom.budget_deferred").incrementAndGet();
          do {
            if (shutdownDeadline != 0 && System.nanoTime() >= shutdownDeadline) {
              loss("sbom.shutdown_pending");
              return;
            }
            Thread.sleep(25);
            now = nanoClock.getAsLong() / 1000000000L;
          } while (now == second);
          second = now;
          events = 0;
          bytes = 0;
        }
        {
          events++;
          bytes += encoded.bytes.length;
          if (entry.priority == 0) {
            normalEvents++;
            normalBytes += encoded.bytes.length;
          }
        }
        export(entry, encoded, channel);
        counter(channel + ".processed").incrementAndGet();
      } catch (InterruptedException interrupted) {
        Thread.currentThread().interrupt();
        return;
      } catch (Throwable error) {
        loss(channel + ".failed");
        logFailure(error);
      }
    }
    if (channel.equals("security")) {
      closeWriter();
    }
  }

  private Encoded encode(Map<String, Object> input) throws IOException {
    Map<String, Object> event = Events.exported(input);
    byte[] encoded = json.writeValueAsBytes(event);
    boolean truncated = encoded.length > maxBytes;
    if (encoded.length > maxBytes) {
      event = new LinkedHashMap<>(event);
      if ("beacon.security.finding".equals(event.get("event_name"))) {
        for (String field : new String[] {"propagation", "ranges", "sources", "stack"}) {
          event.remove(field);
        }
        event.put("evidence_sampled", false);
        event.put("evidence_sample_reason", "record_byte_limit");
      } else {
        event.remove("propagation");
        event.remove("ranges");
        event.remove("sources");
      }
      event.put("truncated", true);
      event.put("truncation_reason", "record_byte_limit");
      encoded = json.writeValueAsBytes(event);
    }
    if (encoded.length > maxBytes) {
      counter("record_limit_exceeded").incrementAndGet();
      throw new IOException("record_limit");
    }
    return new Encoded(event, encoded, truncated);
  }

  private void export(Entry entry, Encoded encoded, String channel) {
    Map<String, Object> event = encoded.event;
    String body = new String(encoded.bytes, UTF_8);
    try {
      GlobalOpenTelemetry.get()
          .getLogsBridge()
          .loggerBuilder(Events.PRODUCT)
          .setInstrumentationVersion(Identity.VERSION)
          .build()
          .logRecordBuilder()
          .setContext(entry.context)
          .setTimestamp(System.currentTimeMillis(), MILLISECONDS)
          .setSeverity(Severity.INFO)
          .setSeverityText("INFO")
          .setBody(body)
          .setEventName(String.valueOf(event.get("event_name")))
          .setAttribute(AttributeKey.stringKey("source"), String.valueOf(event.get("source")))
          .setAttribute(
              AttributeKey.stringKey("event.name"), String.valueOf(event.get("event_name")))
          .emit();
      lastOtelCall = System.currentTimeMillis();
      counter(channel + ".otel_api_emitted").incrementAndGet();
    } catch (Throwable error) {
      counter(channel + ".otel_api_failed").incrementAndGet();
      logFailure(error);
    }
    if (channel.equals("security") && (entry.evidence || encoded.truncated) && file != null) {
      try {
        if (writer == null) {
          openWriter();
        }
        if (fileBytes + encoded.bytes.length + 1 > rotateBytes) {
          rotate();
        }
        writer.write(body);
        writer.newLine();
        writer.flush();
        fileBytes += encoded.bytes.length + 1;
        lastFileSuccess = System.currentTimeMillis();
        counter("beacon.security.file_written").incrementAndGet();
      } catch (IOException error) {
        counter("beacon.security.file_failed").incrementAndGet();
        closeWriter();
        logFailure(error);
      }
    }
  }

  private void openWriter() throws IOException {
    Files.createDirectories(file.getParent());
    fileBytes = Files.exists(file) ? Files.size(file) : 0;
    writer =
        Files.newBufferedWriter(file, UTF_8, StandardOpenOption.CREATE, StandardOpenOption.APPEND);
  }

  private void rotate() throws IOException {
    closeWriter();
    for (int i = backups; i >= 1; i--) {
      Path target = Paths.get(file + "." + i);
      Path source = i == 1 ? file : Paths.get(file + "." + (i - 1));
      if (Files.exists(source)) {
        Files.move(source, target, StandardCopyOption.REPLACE_EXISTING);
      }
    }
    openWriter();
  }

  private void closeWriter() {
    try {
      if (writer != null) {
        writer.close();
      }
    } catch (IOException ignored) {
      // Closing is best effort; delivery failures are tracked before the writer reaches here.
    } finally {
      writer = null;
    }
  }

  private void logFailure(Throwable error) {
    long now = System.currentTimeMillis();
    if (now - lastError > 30000) {
      lastError = now;
      logger.log(WARNING, "[BeaconSecurity] export failure: {0}", error.getClass().getSimpleName());
    }
  }

  @Override
  public void close() {
    synchronized (shutdownComplete) {
      if (!closing) {
        closing = true;
        shutdownDeadline =
            System.nanoTime()
                + MILLISECONDS.toNanos(
                    Settings.limit("beacon.security.export.close.timeout.millis", 3000));
        if (monitoring != null) {
          monitoring.cancel(false);
        }
        try {
          monitor.execute(this::finishClose);
        } catch (RejectedExecutionException error) {
          markShutdownIncomplete();
          running = false;
          shutdownComplete.countDown();
        }
        monitor.shutdown();
      }
    }
    try {
      if (!shutdownComplete.await(Math.max(0, shutdownDeadline - System.nanoTime()), NANOSECONDS)) {
        markShutdownIncomplete();
      }
    } catch (InterruptedException error) {
      markShutdownIncomplete();
      Thread.currentThread().interrupt();
    }
    if (shutdownIncomplete.get()) {
      running = false;
      discardPending(queue, "security");
      discardPending(evidenceQueue, "security");
      discardPending(sbomQueue, "sbom");
    }
  }

  private void finishClose() {
    // The existing daemon monitor owns all shutdown I/O. A stuck filesystem
    // must not keep the application's shutdown hook waiting past its deadline.
    try {
      ledger.tick(delivery(), true);
      running = false;
      joinUntilDeadline(worker);
      joinUntilDeadline(sbomWorker);
      if (worker.isAlive() || sbomWorker.isAlive() || System.nanoTime() >= shutdownDeadline) {
        markShutdownIncomplete();
      }
      discardPending(queue, "security");
      discardPending(evidenceQueue, "security");
      discardPending(sbomQueue, "sbom");
      boolean incomplete = shutdownIncomplete.get();
      ledger.tick(delivery(), true);
      if (System.nanoTime() >= shutdownDeadline) {
        markShutdownIncomplete();
      }
      if (!incomplete && shutdownIncomplete.get()) {
        ledger.tick(delivery(), true);
      }
    } catch (InterruptedException error) {
      Thread.currentThread().interrupt();
      markShutdownIncomplete();
      logFailure(error);
    } catch (Throwable error) {
      markShutdownIncomplete();
      logFailure(error);
    } finally {
      running = false;
      shutdownComplete.countDown();
    }
  }

  private void joinUntilDeadline(Thread thread) throws InterruptedException {
    long remaining = shutdownDeadline - System.nanoTime();
    if (remaining > 0) {
      NANOSECONDS.timedJoin(thread, remaining);
    }
  }

  private void markShutdownIncomplete() {
    if (shutdownIncomplete.compareAndSet(false, true)) {
      ledger.shutdownIncomplete();
      counter("beacon.security.shutdown_failed").incrementAndGet();
    }
  }

  private void discardPending(ArrayBlockingQueue<Entry> pending, String channel) {
    List<Entry> discarded = new ArrayList<>();
    pending.drainTo(discarded);
    for (Entry ignored : discarded) {
      loss(channel + ".shutdown_pending");
    }
  }

  private static int priority(Map<String, Object> event) {
    return "suspected".equals(AttackEvidence.status(event)) ? 2 : 0;
  }

  private static final class Encoded {
    final Map<String, Object> event;
    final byte[] bytes;
    final boolean truncated;

    Encoded(Map<String, Object> event, byte[] bytes, boolean truncated) {
      this.event = event;
      this.bytes = bytes;
      this.truncated = truncated;
    }
  }

  private static final class Entry {
    final Map<String, Object> event;
    final Context context;
    final boolean evidence;
    final int priority;

    Entry(Map<String, Object> event, Context context, boolean evidence, int priority) {
      this.event = event;
      this.context = context;
      this.evidence = evidence;
      this.priority = priority;
    }
  }
}

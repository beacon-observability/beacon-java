/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.beacon.security.exporter;

import static io.beacon.security.core.Values.map;
import static io.opentelemetry.api.common.AttributeKey.stringKey;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Arrays.asList;
import static java.util.Collections.emptyList;
import static java.util.concurrent.TimeUnit.MILLISECONDS;
import static java.util.concurrent.TimeUnit.NANOSECONDS;
import static java.util.concurrent.TimeUnit.SECONDS;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.beacon.security.core.Identity;
import io.beacon.security.core.SecurityState;
import io.opentelemetry.api.GlobalOpenTelemetry;
import io.opentelemetry.api.logs.Severity;
import io.opentelemetry.context.Context;
import io.opentelemetry.sdk.OpenTelemetrySdk;
import io.opentelemetry.sdk.common.CompletableResultCode;
import io.opentelemetry.sdk.logs.SdkLoggerProvider;
import io.opentelemetry.sdk.logs.data.LogRecordData;
import io.opentelemetry.sdk.logs.export.LogRecordExporter;
import io.opentelemetry.sdk.logs.export.SimpleLogRecordProcessor;
import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.BooleanSupplier;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class EvidenceExporterTest {
  private static final String[] SETTINGS = {
    "beacon.security.export.queue.size",
    "beacon.security.export.sbom.queue.size",
    "beacon.security.export.security.events-per-second",
    "beacon.security.export.security.bytes-per-second",
    "beacon.security.export.sbom.events-per-second",
    "beacon.security.export.sbom.bytes-per-second",
    "beacon.security.evidence.max.bytes",
    "beacon.security.evidence.file",
    "beacon.security.evidence.file.max.bytes",
    "beacon.security.evidence.file.backups",
    "beacon.security.export.close.timeout.millis",
    "beacon.security.local-output.enabled",
    "beacon.security.output"
  };

  private final Map<String, String> previousSettings = new HashMap<>();
  private final ObjectMapper json = new ObjectMapper();

  @BeforeEach
  void captureSettings() {
    for (String key : SETTINGS) previousSettings.put(key, System.getProperty(key));
    System.setProperty("beacon.security.local-output.enabled", "true");
    GlobalOpenTelemetry.resetForTest();
  }

  @AfterEach
  void restoreSettings() {
    GlobalOpenTelemetry.resetForTest();
    for (String key : SETTINGS) {
      String value = previousSettings.get(key);
      if (value == null) System.clearProperty(key);
      else System.setProperty(key, value);
    }
  }

  @Test
  void emitsLogsWithoutTraceSampling(@TempDir Path temp) throws Exception {
    CapturingExporter logs = new CapturingExporter();
    OpenTelemetrySdk sdk = installLogs(logs);
    Path file = temp.resolve("evidence.jsonl");
    System.setProperty("beacon.security.evidence.file", file.toString());
    EvidenceExporter exporter = new EvidenceExporter();
    try {
      exporter.emit(
          map("event_name", "beacon.security.finding", "evidence_id", "ev-always-off"),
          Context.root(),
          true);
    } finally {
      exporter.close();
      sdk.close();
    }

    assertTrue(logs.records.size() >= 1);
    assertTrue(logs.bodies().stream().anyMatch(body -> body.contains("ev-always-off")));
    LogRecordData securityRecord =
        logs.records.stream()
            .filter(record -> record.getBodyValue().asString().contains("ev-always-off"))
            .findFirst()
            .orElseThrow(() -> new AssertionError("security log record missing"));
    assertEquals("io.beacon.security", securityRecord.getInstrumentationScopeInfo().getName());
    assertEquals(Identity.VERSION, securityRecord.getInstrumentationScopeInfo().getVersion());
    assertEquals(Severity.INFO, securityRecord.getSeverity());
    assertEquals("INFO", securityRecord.getSeverityText());
    assertEquals("beacon.security.finding", securityRecord.getEventName());
    assertEquals("beacon_security", securityRecord.getAttributes().get(stringKey("source")));
    assertEquals(
        "beacon.security.finding", securityRecord.getAttributes().get(stringKey("event.name")));
    assertTrue(Files.exists(file));
    assertTrue(
        Files.readAllLines(file, UTF_8).stream().anyMatch(line -> line.contains("ev-always-off")));
  }

  @Test
  void dropsWhenBoundedQueueIsBlockedButDoesNotThrow() throws Exception {
    System.setProperty("beacon.security.export.queue.size", "1");
    BlockingExporter logs = new BlockingExporter();
    OpenTelemetrySdk sdk = installLogs(logs);
    EvidenceExporter exporter = new EvidenceExporter();
    try {
      exporter.emit(map("event_name", "beacon.security.first"), Context.root(), false);
      assertTrue(logs.started.await(5, SECONDS));
      for (int i = 0; i < 1000; i++) {
        exporter.emit(
            map("event_name", "beacon.security.queue", "index", i), Context.root(), false);
      }
      assertTrue(exporter.dropped() > 0);
    } finally {
      logs.release.countDown();
      exporter.close();
      sdk.close();
    }
  }

  @Test
  void queuesSbomIndependentlyWhileSecurityWorkerIsBlocked(@TempDir Path temp) throws Exception {
    System.setProperty("beacon.security.output", temp.resolve("ledger").toString());
    ChannelBlockingExporter logs = new ChannelBlockingExporter();
    OpenTelemetrySdk sdk = installLogs(logs);
    EvidenceExporter exporter = new EvidenceExporter();
    try {
      exporter.emit(map("event_name", "beacon.security.block"), Context.root(), false);
      assertTrue(logs.securityStarted.await(5, SECONDS));

      for (int i = 0; i < 32; i++) {
        exporter.emit(
            map("event_name", "beacon.security.sbom.snapshot", "revision", 7, "index", i),
            Context.root(),
            false);
      }
      assertTrue(
          await(() -> counter(exporter.delivery(), "sbom.queued") >= 32, 1000),
          "SBOM enqueue must not wait for the security queue worker");
      logs.release.countDown();
      assertTrue(
          logs.sbomReceived.await(5, SECONDS),
          "SBOM records must drain after the shared OTel processor is released");
      assertTrue(
          logs.bodies().stream().anyMatch(body -> body.contains("beacon.security.sbom.snapshot")));
    } finally {
      logs.release.countDown();
      exporter.close();
      sdk.close();
    }
  }

  @Test
  void enforcesIndependentPerChannelBudgets(@TempDir Path temp) throws Exception {
    System.setProperty("beacon.security.output", temp.resolve("ledger").toString());
    System.setProperty("beacon.security.export.security.events-per-second", "1");
    System.setProperty("beacon.security.export.sbom.events-per-second", "1");
    System.setProperty("beacon.security.export.security.bytes-per-second", "65536");
    System.setProperty("beacon.security.export.sbom.bytes-per-second", "65536");
    CapturingExporter logs = new CapturingExporter();
    OpenTelemetrySdk sdk = installLogs(logs);
    EvidenceExporter exporter = new EvidenceExporter();
    try {
      for (int i = 0; i < 3; i++) {
        exporter.emit(
            map("event_name", "beacon.security.budget", "index", i), Context.root(), false);
        exporter.emit(
            map(
                "event_name",
                "beacon.security.sbom.snapshot",
                "dependencies",
                emptyList(),
                "index",
                i),
            Context.root(),
            false);
      }
      assertTrue(await(() -> counter(exporter.delivery(), "security.budget_exceeded") > 0, 5000));
      assertTrue(await(() -> counter(exporter.delivery(), "sbom.processed") == 3, 5000));
      assertTrue(counter(exporter.delivery(), "sbom.budget_deferred") > 0);
      assertEquals(0, counter(exporter.delivery(), "sbom.budget_exceeded"));
    } finally {
      exporter.close();
      sdk.close();
    }
  }

  @Test
  void enforcesPerChannelByteBudgets(@TempDir Path temp) throws Exception {
    System.setProperty("beacon.security.output", temp.resolve("ledger").toString());
    System.setProperty("beacon.security.export.security.events-per-second", "100");
    System.setProperty("beacon.security.export.sbom.events-per-second", "100");
    System.setProperty("beacon.security.export.security.bytes-per-second", "256");
    System.setProperty("beacon.security.export.sbom.bytes-per-second", "256");
    OpenTelemetrySdk sdk = installLogs(new CapturingExporter());
    EvidenceExporter exporter = new EvidenceExporter();
    try {
      for (int i = 0; i < 4; i++) {
        exporter.emit(
            map("event_name", "beacon.security.byte-budget", "payload", repeat('b', 200)),
            Context.root(),
            false);
        exporter.emit(
            map("event_name", "beacon.security.sbom.component", "payload", repeat('s', 200)),
            Context.root(),
            false);
      }
      assertTrue(await(() -> counter(exporter.delivery(), "security.budget_exceeded") > 0, 5000));
      assertTrue(await(() -> counter(exporter.delivery(), "sbom.budget_exceeded") > 0, 5000));
    } finally {
      exporter.close();
      sdk.close();
    }
  }

  @Test
  void emitsExplicitLossRecordWhenBudgetDropsEvents(@TempDir Path temp) throws Exception {
    System.setProperty("beacon.security.output", temp.resolve("ledger").toString());
    System.setProperty("beacon.security.export.security.events-per-second", "1");
    System.setProperty("beacon.security.export.security.bytes-per-second", "65536");
    CapturingExporter logs = new CapturingExporter();
    OpenTelemetrySdk sdk = installLogs(logs);
    EvidenceExporter exporter = new EvidenceExporter();
    try {
      for (int i = 0; i < 8; i++) {
        exporter.emit(map("event_name", "beacon.security.loss", "index", i), Context.root(), false);
      }
      assertTrue(await(() -> counter(exporter.delivery(), "security.budget_exceeded") > 0, 5000));
      assertTrue(
          await(
              () ->
                  logs.bodies().stream()
                      .anyMatch(body -> body.contains("beacon.security.export.dropped")),
              5000),
          "budget loss must be represented by an explicit diagnostic event");
      String loss =
          logs.bodies().stream()
              .filter(body -> body.contains("beacon.security.export.dropped"))
              .findFirst()
              .orElse("");
      assertTrue(loss.contains("security"));
      assertTrue(loss.contains("budget_exceeded"));
    } finally {
      exporter.close();
      sdk.close();
    }
  }

  @Test
  void doesNotClaimBackendAcknowledgementFromOtelEmit(@TempDir Path temp) throws Exception {
    System.setProperty("beacon.security.output", temp.resolve("ledger").toString());
    CapturingExporter logs = new CapturingExporter();
    OpenTelemetrySdk sdk = installLogs(logs);
    EvidenceExporter exporter = new EvidenceExporter();
    try {
      exporter.emit(map("event_name", "beacon.security.ack-semantic"), Context.root(), false);
      assertTrue(await(() -> counter(exporter.delivery(), "security.otel_api_emitted") > 0, 5000));
      Map<String, Object> delivery = exporter.delivery();
      assertEquals("unknown", delivery.get("backend_acknowledgement"));
      assertEquals("api_emit_is_not_export_or_backend_ack", delivery.get("otel_semantics"));
    } finally {
      exporter.close();
      sdk.close();
    }
  }

  @Test
  void separatesSbomLogSourcesThroughNormalAndTruncatedDelivery(@TempDir Path temp)
      throws Exception {
    System.setProperty("beacon.security.output", temp.toString());
    CapturingExporter logs = new CapturingExporter();
    OpenTelemetrySdk sdk = installLogs(logs);
    String[][] cases = {
      {"beacon.security.finding", "beacon_security"},
      {"beacon.security.sbom.snapshot", "beacon_security_sbom"},
      {"beacon.security.sbom.health", "beacon_security_sbom"},
      {"beacon.security.sbom.update_failed", "beacon_security_sbom"},
      {"beacon.security.sbom.export.dropped", "beacon_security_sbom"}
    };
    try {
      for (int maxBytes : new int[] {65536, 256, 128}) {
        System.setProperty("beacon.security.evidence.max.bytes", Integer.toString(maxBytes));
        for (String[] item : cases) {
          int start = logs.records.size();
          EvidenceExporter exporter = new EvidenceExporter();
          try {
            exporter.emit(
                map(
                    "event_name",
                    item[0],
                    "source",
                    "caller-override",
                    "sbom_id",
                    "source-test",
                    "payload",
                    repeat('x', 4096)),
                Context.root(),
                false);
          } finally {
            exporter.close();
          }
          assertEquals(start + 1, logs.records.size());
          LogRecordData log = logs.records.get(start);
          Map<?, ?> body = json.readValue(log.getBodyValue().asString(), Map.class);
          assertEquals(item[1], log.getAttributes().get(stringKey("source")));
          assertEquals(item[1], body.get("source"));
          assertEquals(body.get("event_name"), log.getEventName());
          assertEquals(body.get("event_name"), log.getAttributes().get(stringKey("event.name")));
          assertTrue(log.getBodyValue().asString().getBytes(UTF_8).length <= maxBytes);
          if (maxBytes == 65536) assertEquals(item[0], body.get("event_name"));
          else {
            assertEquals("beacon.security.export.truncated", body.get("event_name"));
            assertEquals(maxBytes == 256 ? item[0] : null, body.get("original_event"));
          }
        }
      }
    } finally {
      sdk.close();
    }
  }

  @Test
  void truncatesRecordsBeforeWritingThem(@TempDir Path temp) throws Exception {
    System.setProperty("beacon.security.evidence.max.bytes", "256");
    Path file = temp.resolve("bounded.jsonl");
    System.setProperty("beacon.security.evidence.file", file.toString());
    CapturingExporter logs = new CapturingExporter();
    OpenTelemetrySdk sdk = installLogs(logs);
    EvidenceExporter exporter = new EvidenceExporter();
    try {
      List<String> large = new ArrayList<>();
      for (int i = 0; i < 80; i++) large.add("secret-value-" + i + repeat('x', 80));
      exporter.emit(
          map(
              "event_name",
              "beacon.security.finding",
              "evidence_id",
              "ev-large",
              "sources",
              large,
              "propagation",
              large,
              "ranges",
              large,
              "details",
              repeat('x', 2000)),
          Context.root(),
          true);
    } finally {
      exporter.close();
      sdk.close();
    }

    List<String> lines = Files.readAllLines(file, UTF_8);
    assertEquals(1, lines.size());
    assertTrue(lines.get(0).getBytes(UTF_8).length <= 256);
    Map<?, ?> record = json.readValue(lines.get(0), Map.class);
    assertEquals("beacon.security.export.truncated", record.get("event_name"));
    assertTrue(Boolean.TRUE.equals(record.get("truncated")));
    assertEquals("beacon_security", record.get("source"));

    LogRecordData log =
        logs.records.stream()
            .filter(item -> "beacon.security.export.truncated".equals(item.getEventName()))
            .findFirst()
            .orElseThrow(() -> new AssertionError("truncated OTel record missing"));
    assertEquals("beacon.security.export.truncated", log.getEventName());
    assertEquals(
        "beacon.security.export.truncated", log.getAttributes().get(stringKey("event.name")));
    assertEquals("beacon_security", log.getAttributes().get(stringKey("source")));
    assertEquals("io.beacon.security", log.getInstrumentationScopeInfo().getName());
    assertEquals(Identity.VERSION, log.getInstrumentationScopeInfo().getVersion());
    assertEquals(Severity.INFO, log.getSeverity());
    assertEquals(9, log.getSeverity().getSeverityNumber());
    assertEquals("INFO", log.getSeverityText());
    Map<?, ?> otelBody = json.readValue(log.getBodyValue().asString(), Map.class);
    assertEquals("beacon.security.export.truncated", otelBody.get("event_name"));
    assertEquals("beacon_security", otelBody.get("source"));
    assertTrue(Boolean.TRUE.equals(otelBody.get("truncated")));
  }

  @Test
  void rotatesEvidenceFilesWithinBackupLimit(@TempDir Path temp) throws Exception {
    System.setProperty("beacon.security.evidence.file.max.bytes", "256");
    System.setProperty("beacon.security.evidence.file.backups", "2");
    Path file = temp.resolve("rotating.jsonl");
    System.setProperty("beacon.security.evidence.file", file.toString());
    EvidenceExporter exporter = new EvidenceExporter();
    try {
      for (int i = 0; i < 30; i++) {
        exporter.emit(
            map("event_name", "beacon.security.rotation", "index", i, "payload", repeat('r', 80)),
            Context.root(),
            true);
      }
    } finally {
      exporter.close();
    }

    assertTrue(Files.exists(file));
    assertTrue(Files.exists(temp.resolve("rotating.jsonl.1")));
    assertTrue(Files.exists(temp.resolve("rotating.jsonl.2")));
    for (Path candidate :
        asList(file, temp.resolve("rotating.jsonl.1"), temp.resolve("rotating.jsonl.2"))) {
      for (String line : Files.readAllLines(candidate, UTF_8)) {
        assertNotNull(json.readValue(line, Map.class));
      }
    }
  }

  @Test
  void anUnwritableEvidenceDirectoryDoesNotBreakTheCaller(@TempDir Path temp) throws Exception {
    Path parent = temp.resolve("unwritable");
    Files.createDirectories(parent);
    Path file = parent.resolve("evidence.jsonl");
    Set<PosixFilePermission> writable = PosixFilePermissions.fromString("rwx------");
    Set<PosixFilePermission> readOnly = PosixFilePermissions.fromString("r-x------");
    try {
      Files.setPosixFilePermissions(parent, readOnly);
    } catch (UnsupportedOperationException error) {
      return;
    }
    try {
      assumeTrue(!Files.isWritable(parent), "requires a non-root POSIX test process");
      System.setProperty("beacon.security.evidence.file", file.toString());
      EvidenceExporter exporter = new EvidenceExporter();
      try {
        exporter.emit(map("event_name", "beacon.security.unwritable"), Context.root(), true);
      } finally {
        exporter.close();
      }
      assertFalse(Files.exists(file));
    } finally {
      Files.setPosixFilePermissions(parent, writable);
    }
  }

  @Test
  void closeDeadlineCoversABlockedMonitorAndRepeatedClose(@TempDir Path temp) throws Exception {
    System.setProperty("beacon.security.output", temp.toString());
    System.setProperty("beacon.security.export.close.timeout.millis", "60");
    Path control = temp.resolve("control.json");
    Files.write(
        control,
        json.writeValueAsBytes(
            map(
                "revision",
                "start",
                "run",
                map(
                    "run_id",
                    "closing",
                    "case_id",
                    "closing",
                    "rule",
                    "sql_injection",
                    "expires_at",
                    Instant.now().plusSeconds(60).toString(),
                    "conditions",
                    map("suite", "close", "fixture", "close", "expected_requests", 1)))));
    EvidenceExporter exporter = new EvidenceExporter();
    exporter.ledger().tick(exporter.delivery(), event -> {}, true);
    SecurityState request = new SecurityState();
    exporter.ledger().begin(request);
    exporter.ledger().end(request);
    request.close();
    Files.write(control, json.writeValueAsBytes(map("revision", "stop")));
    exporter.ledger().tick(exporter.delivery(), event -> {}, true);
    ExecutorService thread = Executors.newSingleThreadExecutor();
    try {
      synchronized (exporter.ledger()) {
        thread.submit(exporter::close).get(1, SECONDS);
        thread.submit(exporter::close).get(1, SECONDS);
        assertEquals(1L, counter(exporter.delivery(), "beacon.security.shutdown_failed"));
      }
      assertTrue(
          await(
              () -> {
                try {
                  Map<?, ?> health =
                      json.readValue(Files.readAllBytes(temp.resolve("health.json")), Map.class);
                  return ((Number) health.get("delivery_loss")).longValue() > 0;
                } catch (IOException error) {
                  return false;
                }
              },
              3000));
      Map<?, ?> run =
          (Map<?, ?>)
              ((List<?>)
                      json.readValue(Files.readAllBytes(temp.resolve("runs.json")), Map.class)
                          .get("runs"))
                  .get(0);
      assertTrue(((Number) run.get("delivery_loss")).longValue() > 0);
      assertTrue(((Number) run.get("incomplete_requests")).longValue() > 0);
    } finally {
      exporter.close();
      awaitMonitorTermination(exporter);
      thread.shutdownNow();
      assertTrue(thread.awaitTermination(2, SECONDS));
    }
  }

  @Test
  void closeUsesOneDeadlineForBlockedDeliveryAndFinalSnapshots(@TempDir Path temp)
      throws Exception {
    System.setProperty("beacon.security.output", temp.toString());
    System.setProperty("beacon.security.export.close.timeout.millis", "80");
    BlockingExporter logs = new BlockingExporter();
    OpenTelemetrySdk sdk = installLogs(logs);
    EvidenceExporter exporter = new EvidenceExporter();
    try {
      exporter.emit(map("event_name", "beacon.security.blocked-close"), Context.root(), true);
      assertTrue(logs.started.await(2, SECONDS));
      long started = System.nanoTime();
      exporter.close();
      assertTrue(NANOSECONDS.toMillis(System.nanoTime() - started) < 1000);
      assertEquals(1L, counter(exporter.delivery(), "beacon.security.shutdown_failed"));
    } finally {
      logs.release.countDown();
      exporter.close();
      awaitMonitorTermination(exporter);
      sdk.close();
    }
  }

  private static void awaitMonitorTermination(EvidenceExporter exporter) throws Exception {
    Field field = EvidenceExporter.class.getDeclaredField("monitor");
    field.setAccessible(true);
    assertTrue(((ExecutorService) field.get(exporter)).awaitTermination(3, SECONDS));
  }

  private static OpenTelemetrySdk installLogs(LogRecordExporter exporter) {
    SdkLoggerProvider provider =
        SdkLoggerProvider.builder()
            .addLogRecordProcessor(SimpleLogRecordProcessor.create(exporter))
            .build();
    OpenTelemetrySdk sdk = OpenTelemetrySdk.builder().setLoggerProvider(provider).build();
    GlobalOpenTelemetry.set(sdk);
    return sdk;
  }

  private static String repeat(char value, int count) {
    StringBuilder result = new StringBuilder(count);
    for (int i = 0; i < count; i++) result.append(value);
    return result.toString();
  }

  @SuppressWarnings("unchecked")
  private static long counter(Map<String, Object> delivery, String key) {
    Object counters = delivery.get("counters");
    if (!(counters instanceof Map)) return 0;
    Object value = ((Map<String, Object>) counters).get(key);
    return value instanceof Number ? ((Number) value).longValue() : 0;
  }

  private static boolean await(BooleanSupplier condition, long timeoutMillis)
      throws InterruptedException {
    long deadline = System.nanoTime() + MILLISECONDS.toNanos(timeoutMillis);
    do {
      if (condition.getAsBoolean()) return true;
      Thread.sleep(25);
    } while (System.nanoTime() < deadline);
    return condition.getAsBoolean();
  }

  private static class CapturingExporter implements LogRecordExporter {
    final List<LogRecordData> records = new ArrayList<>();

    @Override
    public synchronized CompletableResultCode export(Collection<LogRecordData> batch) {
      records.addAll(batch);
      return CompletableResultCode.ofSuccess();
    }

    @Override
    public CompletableResultCode flush() {
      return CompletableResultCode.ofSuccess();
    }

    @Override
    public CompletableResultCode shutdown() {
      return CompletableResultCode.ofSuccess();
    }

    synchronized List<String> bodies() {
      List<String> result = new ArrayList<>();
      for (LogRecordData record : records) result.add(record.getBodyValue().asString());
      return result;
    }
  }

  private static final class BlockingExporter extends CapturingExporter {
    final CountDownLatch started = new CountDownLatch(1);
    final CountDownLatch release = new CountDownLatch(1);
    private final AtomicBoolean first = new AtomicBoolean();

    @Override
    public synchronized CompletableResultCode export(Collection<LogRecordData> batch) {
      super.export(batch);
      if (first.compareAndSet(false, true)) {
        started.countDown();
        try {
          release.await(5, SECONDS);
        } catch (InterruptedException error) {
          Thread.currentThread().interrupt();
        }
      }
      return CompletableResultCode.ofSuccess();
    }
  }

  private static final class ChannelBlockingExporter extends CapturingExporter {
    final CountDownLatch securityStarted = new CountDownLatch(1);
    final CountDownLatch release = new CountDownLatch(1);
    final CountDownLatch sbomReceived = new CountDownLatch(1);
    private final AtomicBoolean blockOnce = new AtomicBoolean();

    @Override
    public synchronized CompletableResultCode export(Collection<LogRecordData> batch) {
      super.export(batch);
      boolean security = false;
      boolean sbom = false;
      for (LogRecordData record : batch) {
        String body = record.getBodyValue().asString();
        security |= body.contains("beacon.security.block");
        sbom |= body.contains("beacon.security.sbom.snapshot");
      }
      if (sbom) sbomReceived.countDown();
      if (security && blockOnce.compareAndSet(false, true)) {
        securityStarted.countDown();
        try {
          release.await(5, SECONDS);
        } catch (InterruptedException error) {
          Thread.currentThread().interrupt();
        }
      }
      return CompletableResultCode.ofSuccess();
    }
  }
}

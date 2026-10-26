/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.beacon.testing.jdbc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.protobuf.ByteString;
import com.sun.net.httpserver.HttpServer;
import io.opentelemetry.proto.collector.logs.v1.ExportLogsServiceRequest;
import io.opentelemetry.proto.collector.metrics.v1.ExportMetricsServiceRequest;
import io.opentelemetry.proto.collector.trace.v1.ExportTraceServiceRequest;
import io.opentelemetry.proto.common.v1.KeyValue;
import io.opentelemetry.proto.trace.v1.Span;
import io.opentelemetry.proto.trace.v1.Status;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.testcontainers.postgresql.PostgreSQLContainer;

class JdbcSmokeTest {
  private static final PostgreSQLContainer postgres = new PostgreSQLContainer("postgres:16.15");
  private static final String TRACE_ID = "12345678901234567890123456789012";
  private static final String PARENT_ID = "1234567890123456";

  @TempDir Path directory;

  @BeforeAll
  static void startDatabase() {
    postgres.start();
  }

  @AfterAll
  static void stopDatabase() {
    postgres.stop();
  }

  @ParameterizedTest
  @MethodSource("configurations")
  void exportsPostgresChildSpans(boolean logsAndMetrics, boolean security) throws Exception {
    List<Span> spans = new CopyOnWriteArrayList<>();
    Map<ByteString, String> scopes = new ConcurrentHashMap<>();
    List<ExportLogsServiceRequest> logs = new CopyOnWriteArrayList<>();
    List<ExportMetricsServiceRequest> metrics = new CopyOnWriteArrayList<>();
    List<Throwable> receiverErrors = new CopyOnWriteArrayList<>();
    HttpServer receiver = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    receiver.createContext(
        "/v1/",
        exchange -> {
          try (exchange) {
            assertThat(exchange.getRequestHeaders().getFirst("Content-Type"))
                .isEqualTo("application/x-protobuf");
            byte[] bytes = exchange.getRequestBody().readAllBytes();
            switch (exchange.getRequestURI().getPath()) {
              case "/v1/traces":
                ExportTraceServiceRequest.parseFrom(bytes)
                    .getResourceSpansList()
                    .forEach(
                        resource -> {
                          assertThat(
                                  attribute(
                                      resource.getResource().getAttributesList(), "service.name"))
                              .isEqualTo("beacon-jdbc-smoke");
                          resource
                              .getScopeSpansList()
                              .forEach(
                                  scope -> {
                                    scope
                                        .getSpansList()
                                        .forEach(
                                            span ->
                                                scopes.put(
                                                    span.getSpanId(), scope.getScope().getName()));
                                    spans.addAll(scope.getSpansList());
                                  });
                        });
                break;
              case "/v1/logs":
                logs.add(ExportLogsServiceRequest.parseFrom(bytes));
                break;
              case "/v1/metrics":
                metrics.add(ExportMetricsServiceRequest.parseFrom(bytes));
                break;
              default:
                throw new AssertionError(exchange.getRequestURI());
            }
            exchange.getResponseHeaders().set("Content-Type", "application/x-protobuf");
            exchange.sendResponseHeaders(200, -1);
          } catch (Throwable t) {
            receiverErrors.add(t);
          }
        });
    receiver.start();
    Process application = null;
    Path output = directory.resolve("application.log");
    try {
      List<String> command = new ArrayList<>();
      command.add(Path.of(System.getProperty("java.home"), "bin", "java").toString());
      command.add("-javaagent:" + System.getProperty("agentPath"));
      command.add("-jar");
      command.add(System.getProperty("fixturePath"));
      command.add("--server.port=0");
      command.add("--spring.datasource.url=" + postgres.getJdbcUrl());
      command.add("--spring.datasource.username=" + postgres.getUsername());
      command.add("--spring.datasource.password=" + postgres.getPassword());
      ProcessBuilder builder =
          new ProcessBuilder(command).redirectErrorStream(true).redirectOutput(output.toFile());
      // Isolate the fixture from developer/CI telemetry configuration.
      builder
          .environment()
          .keySet()
          .removeIf(key -> key.startsWith("OTEL_") || key.startsWith("BEACON_"));
      builder.environment().remove("JAVA_TOOL_OPTIONS");
      builder.environment().remove("JDK_JAVA_OPTIONS");
      builder.environment().remove("_JAVA_OPTIONS");
      builder
          .environment()
          .putAll(
              Map.ofEntries(
                  Map.entry("OTEL_SERVICE_NAME", "beacon-jdbc-smoke"),
                  Map.entry("OTEL_TRACES_EXPORTER", "otlp"),
                  Map.entry("OTEL_TRACES_SAMPLER", "always_on"),
                  Map.entry("OTEL_LOGS_EXPORTER", logsAndMetrics ? "otlp" : "none"),
                  Map.entry("OTEL_METRICS_EXPORTER", logsAndMetrics ? "otlp" : "none"),
                  Map.entry(
                      "OTEL_INSTRUMENTATION_LOGBACK_APPENDER_ENABLED",
                      Boolean.toString(logsAndMetrics)),
                  Map.entry("OTEL_PROFILING_ENABLED", "false"),
                  Map.entry("OTEL_EXPORTER_OTLP_PROTOCOL", "http/protobuf"),
                  Map.entry(
                      "OTEL_EXPORTER_OTLP_ENDPOINT",
                      "http://127.0.0.1:" + receiver.getAddress().getPort()),
                  Map.entry("OTEL_BSP_SCHEDULE_DELAY", "100"),
                  Map.entry("OTEL_BLRP_SCHEDULE_DELAY", "100"),
                  Map.entry("OTEL_METRIC_EXPORT_INTERVAL", "1000"),
                  Map.entry("BEACON_SECURITY_ENABLED", Boolean.toString(security)),
                  Map.entry("BEACON_SECURITY_SBOM_ENABLED", "true"),
                  Map.entry("BEACON_SECURITY_LOCAL_OUTPUT_ENABLED", "true"),
                  Map.entry("BEACON_SECURITY_OUTPUT", directory.resolve("security").toString())));
      application = builder.start();
      Process running = application;
      Pattern portPattern = Pattern.compile("Tomcat started on port (\\d+)");
      await()
          .atMost(Duration.ofSeconds(60))
          .untilAsserted(
              () -> {
                assertThat(running.isAlive()).isTrue();
                assertThat(portPattern.matcher(Files.readString(output)).find()).isTrue();
              });
      var matcher = portPattern.matcher(Files.readString(output));
      assertThat(matcher.find()).isTrue();
      String endpoint = "http://127.0.0.1:" + matcher.group(1);
      try (HttpClient client =
          HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build()) {
        await()
            .atMost(Duration.ofSeconds(15))
            .untilAsserted(
                () ->
                    assertThat(
                            client
                                .send(
                                    HttpRequest.newBuilder(URI.create(endpoint + "/health"))
                                        .timeout(Duration.ofSeconds(5))
                                        .build(),
                                    HttpResponse.BodyHandlers.ofString())
                                .body())
                        .isEqualTo("ok"));
        // Each HTTP request has a known parent, allowing exact end-to-end trace and JDBC counts.
        for (int i = 0; i < 8; i++) {
          var response =
              client.send(
                  HttpRequest.newBuilder(URI.create(endpoint + "/query?value=guest"))
                      .header("traceparent", "00-" + TRACE_ID + "-" + PARENT_ID + "-01")
                      .timeout(Duration.ofSeconds(15))
                      .build(),
                  HttpResponse.BodyHandlers.ofString());
          assertThat(response.statusCode()).isEqualTo(200);
          assertThat(response.body()).isEqualTo("guest");
        }
      }
      await()
          .atMost(Duration.ofSeconds(20))
          .untilAsserted(
              () -> {
                List<Span> queries =
                    spans.stream()
                        .filter(
                            span ->
                                attribute(span.getAttributesList(), "db.system")
                                        .equals("postgresql")
                                    && attribute(span.getAttributesList(), "db.statement")
                                        .contains("payload"))
                        .toList();
                assertThat(queries).hasSize(8);
                for (Span query : queries) {
                  assertThat(scopes.get(query.getSpanId())).isEqualTo("io.opentelemetry.jdbc");
                  assertThat(attribute(query.getAttributesList(), "db.name"))
                      .isEqualTo(postgres.getDatabaseName());
                  assertThat(attribute(query.getAttributesList(), "db.operation"))
                      .isEqualTo("SELECT");
                  assertThat(query.getKind()).isEqualTo(Span.SpanKind.SPAN_KIND_CLIENT);
                  assertThat(query.getTraceId())
                      .isEqualTo(ByteString.copyFrom(HexFormat.of().parseHex(TRACE_ID)));
                  assertThat(query.getName()).containsIgnoringCase("select");
                  assertThat(query.getStatus().getCode())
                      .isNotEqualTo(Status.StatusCode.STATUS_CODE_ERROR);
                  assertThat(
                          spans.stream()
                              .filter(parent -> parent.getSpanId().equals(query.getParentSpanId()))
                              .toList())
                      .singleElement()
                      .satisfies(
                          parent -> {
                            assertThat(parent.getKind()).isEqualTo(Span.SpanKind.SPAN_KIND_SERVER);
                            assertThat(parent.getTraceId()).isEqualTo(query.getTraceId());
                            assertThat(parent.getParentSpanId())
                                .isEqualTo(ByteString.copyFrom(HexFormat.of().parseHex(PARENT_ID)));
                          });
                }
                if (logsAndMetrics) {
                  assertThat(
                          logs.stream()
                              .flatMap(batch -> batch.getResourceLogsList().stream())
                              .flatMap(resource -> resource.getScopeLogsList().stream())
                              .flatMap(scope -> scope.getLogRecordsList().stream())
                              .map(record -> record.getBody().getStringValue())
                              .toList())
                      .contains("Executing JDBC smoke query");
                  assertThat(
                          metrics.stream()
                              .flatMap(batch -> batch.getResourceMetricsList().stream())
                              .flatMap(resource -> resource.getScopeMetricsList().stream())
                              .flatMap(scope -> scope.getMetricsList().stream())
                              .toList())
                      .isNotEmpty();
                }
                if (security) {
                  ObjectMapper mapper = new ObjectMapper();
                  var health = mapper.readTree(directory.resolve("security/health.json").toFile());
                  assertThat(health.path("effective").asBoolean()).isTrue();
                  var sbom =
                      mapper.readTree(directory.resolve("security/application.cdx.json").toFile());
                  assertThat(sbom.path("components").size()).isPositive();
                }
                assertThat(receiverErrors).isEmpty();
              });
    } finally {
      if (application != null) {
        application.destroy();
        if (!application.waitFor(15, TimeUnit.SECONDS)) {
          application.destroyForcibly();
          application.waitFor(10, TimeUnit.SECONDS);
        }
      }
      receiver.stop(0);
      System.out.println(Files.exists(output) ? Files.readString(output) : "Fixture did not start");
    }
  }

  private static Stream<Arguments> configurations() {
    return Stream.of(
        Arguments.argumentSet("Trace", false, false),
        Arguments.argumentSet("Trace + Logs + Metrics", true, false),
        Arguments.argumentSet("Trace + Security", false, true),
        Arguments.argumentSet("All features", true, true));
  }

  private static String attribute(List<KeyValue> attributes, String key) {
    return attributes.stream()
        .filter(attribute -> attribute.getKey().equals(key))
        .map(attribute -> attribute.getValue().getStringValue())
        .findFirst()
        .orElse("");
  }
}

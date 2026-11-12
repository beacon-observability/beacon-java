/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.javaagent.instrumentation.profiling;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.opentelemetry.sdk.autoconfigure.spi.internal.DefaultConfigProperties;
import java.time.Duration;
import java.util.Map;
import org.junit.jupiter.api.Test;

class AgentProfilingConfigurationTest {
  @Test
  void fileExporterIgnoresUnusedOtlpSettings() {
    var config =
        DefaultConfigProperties.createFromMap(
            Map.of(
                "otel.profiling.exporter", "file",
                "otel.exporter.otlp.profiles.endpoint", "not a URL",
                "otel.exporter.otlp.profiles.protocol", "invalid",
                "otel.exporter.otlp.profiles.timeout", "invalid"));
    assertThat(AgentProfilingConfiguration.create(config).getExporter()).isEqualTo("file");
  }

  @Test
  void otlpIsDefaultAndAppendsPathToSharedEndpoint() {
    var config =
        DefaultConfigProperties.createFromMap(
            Map.of("otel.exporter.otlp.endpoint", "http://localhost:4318/base/"));
    var result = AgentProfilingConfiguration.create(config);
    assertThat(result.getExporter()).isEqualTo("otlp");
    assertThat(result.getOtlpTimeout()).isEqualTo(Duration.ofSeconds(10));
    assertThat(result.getOtlpEndpoint().toString())
        .isEqualTo("http://localhost:4318/base/v1development/profiles");
  }

  @Test
  void signalSettingsOverrideSharedSettings() {
    var config =
        DefaultConfigProperties.createFromMap(
            Map.of(
                "otel.exporter.otlp.profiles.endpoint", "http://localhost:4318/custom",
                "otel.exporter.otlp.profiles.protocol", "http/protobuf",
                "otel.exporter.otlp.protocol", "grpc",
                "otel.exporter.otlp.profiles.headers", "tenant=prod%2Ceast"));
    var result = AgentProfilingConfiguration.create(config);
    assertThat(result.getOtlpEndpoint().toString()).isEqualTo("http://localhost:4318/custom");
    assertThat(result.getOtlpHeaders()).containsEntry("tenant", "prod,east");
  }

  @Test
  void removedExporterIsRejected() {
    var config =
        DefaultConfigProperties.createFromMap(Map.of("otel.profiling.exporter", "datakit"));
    assertThatThrownBy(() -> AgentProfilingConfiguration.create(config))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void unsupportedProtocolIsRejected() {
    var config =
        DefaultConfigProperties.createFromMap(
            Map.of("otel.exporter.otlp.profiles.protocol", "invalid"));
    assertThatThrownBy(() -> AgentProfilingConfiguration.create(config))
        .hasMessageContaining("Unsupported OTLP Profiles protocol");
  }

  @Test
  void grpcDefaultsToPort4317() {
    var config =
        DefaultConfigProperties.createFromMap(
            Map.of("otel.exporter.otlp.profiles.protocol", "grpc"));
    var result = AgentProfilingConfiguration.create(config);
    assertThat(result.getOtlpEndpoint().toString()).isEqualTo("http://localhost:4317");
    assertThat(result.getOtlpProtocol()).isEqualTo("grpc");
  }
}

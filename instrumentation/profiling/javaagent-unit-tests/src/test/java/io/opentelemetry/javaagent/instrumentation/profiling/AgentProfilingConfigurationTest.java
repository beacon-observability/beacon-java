/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.javaagent.instrumentation.profiling;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import io.opentelemetry.sdk.autoconfigure.spi.ConfigProperties;
import io.opentelemetry.sdk.autoconfigure.spi.internal.DefaultConfigProperties;
import java.util.Map;
import org.junit.jupiter.api.Test;

class AgentProfilingConfigurationTest {
  @Test
  void fileExporterIgnoresInvalidDatakitSettings() {
    ConfigProperties config = mock(ConfigProperties.class);
    when(config.getString("otel.profiling.exporter")).thenReturn("file");
    when(config.getString("otel.profiling.endpoint")).thenReturn("not a URL");
    when(config.getDuration("otel.profiling.datakit.timeout"))
        .thenThrow(new IllegalArgumentException("unused timeout"));

    assertThat(AgentProfilingConfiguration.create(config).getExporter()).isEqualTo("file");
  }

  @Test
  void datakitExporterStillValidatesItsEndpoint() {
    ConfigProperties config = mock(ConfigProperties.class);
    when(config.getString("otel.profiling.exporter")).thenReturn("http");
    when(config.getString("otel.profiling.endpoint")).thenReturn("not a URL");

    assertThatThrownBy(() -> AgentProfilingConfiguration.create(config))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("Invalid profiling Datakit endpoint");
  }

  @Test
  void httpNameUsesExistingMultipartEndpointAndKeepsDatakitAlias() {
    for (String exporter : new String[] {"http", "datakit"}) {
      var config =
          DefaultConfigProperties.createFromMap(
              Map.of(
                  "otel.profiling.exporter",
                  exporter,
                  "otel.profiling.endpoint",
                  "http://127.0.0.1:9529/profiling/v1/input"));
      var result = AgentProfilingConfiguration.create(config);
      assertThat(result.getExporter()).isEqualTo("http");
      assertThat(result.getDatakitEndpoint().toString())
          .isEqualTo("http://127.0.0.1:9529/profiling/v1/input");
    }
  }

  @Test
  void defaultsToHttpExporter() {
    assertThat(AgentProfilingConfiguration.create(mock(ConfigProperties.class)).getExporter())
        .isEqualTo("http");
  }

  @Test
  void otlpIsNotAnAliasForMultipartUploads() {
    ConfigProperties config = mock(ConfigProperties.class);
    when(config.getString("otel.profiling.exporter")).thenReturn("otlp");
    assertThatThrownBy(() -> AgentProfilingConfiguration.create(config))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("Unsupported profiling exporter: otlp");
  }
}

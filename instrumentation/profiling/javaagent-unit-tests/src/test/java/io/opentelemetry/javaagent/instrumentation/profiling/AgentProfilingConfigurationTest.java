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
    when(config.getString("otel.profiling.exporter")).thenReturn("datakit");
    when(config.getString("otel.profiling.endpoint")).thenReturn("not a URL");

    assertThatThrownBy(() -> AgentProfilingConfiguration.create(config))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("Invalid profiling Datakit endpoint");
  }
}

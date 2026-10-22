/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.instrumentation.jdbc.internal;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import io.opentelemetry.api.OpenTelemetry;
import io.opentelemetry.api.incubator.ExtendedOpenTelemetry;
import io.opentelemetry.api.incubator.config.DeclarativeConfigProperties;
import org.junit.jupiter.api.Test;
import org.junitpioneer.jupiter.SetSystemProperty;

@SuppressWarnings("deprecation") // using deprecated config property
class JdbcInstrumenterFactoryTest {

  @Test
  void captureQueryParametersDisabledByDefault() {
    assertThat(JdbcInstrumenterFactory.captureQueryParameters(OpenTelemetry.noop())).isFalse();
  }

  @SetSystemProperty(
      key = "otel.instrumentation.jdbc.experimental.capture-query-parameters",
      value = "true")
  @Test
  void captureQueryParametersEnabledByExperimentalProperty() {
    assertThat(JdbcInstrumenterFactory.captureQueryParameters(OpenTelemetry.noop())).isTrue();
  }

  @SetSystemProperty(key = "otel.jdbc.sql.obfuscation", value = "true")
  @Test
  void captureQueryParametersEnabledByCompatibilityProperty() {
    assertThat(JdbcInstrumenterFactory.captureQueryParameters(OpenTelemetry.noop())).isTrue();
  }

  @SetSystemProperty(
      key = "otel.instrumentation.jdbc.experimental.capture-query-parameters",
      value = "false")
  @SetSystemProperty(key = "otel.jdbc.sql.obfuscation", value = "true")
  @Test
  void captureQueryParametersEnabledWhenEitherPropertyIsTrue() {
    assertThat(JdbcInstrumenterFactory.captureQueryParameters(OpenTelemetry.noop())).isTrue();
  }

  @SetSystemProperty(key = "otel.jdbc.sql.obfuscation", value = "true")
  @Test
  void compatibilityTrueIsNotOverriddenByExplicitDeclarativeFalse() {
    ExtendedOpenTelemetry openTelemetry = mock(ExtendedOpenTelemetry.class);
    DeclarativeConfigProperties jdbc = mock(DeclarativeConfigProperties.class);
    when(openTelemetry.getInstrumentationConfig("jdbc")).thenReturn(jdbc);
    when(jdbc.getBoolean("capture_query_parameters/development", false)).thenReturn(false);

    assertThat(JdbcInstrumenterFactory.captureQueryParameters(openTelemetry)).isTrue();
  }
}

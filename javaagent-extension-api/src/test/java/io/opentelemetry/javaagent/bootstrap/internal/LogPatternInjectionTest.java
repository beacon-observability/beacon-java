/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.javaagent.bootstrap.internal;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class LogPatternInjectionTest {
  private static final String FIELDS =
      "service.name=%X{service.name} trace_id=%X{trace_id} span_id=%X{span_id}";

  @ParameterizedTest
  @ValueSource(ints = {0, 1, 2, 3})
  void preservesDateAndIsIdempotent(int framework) {
    String pattern = "[%d{yyyy-MM-dd HH:mm:ss.SSS}] %-5p %m%n";
    String enhanced = LogPatternInjection.enhance(pattern, framework, "trace_id", "span_id");
    assertThat(enhanced).isEqualTo("[%d{yyyy-MM-dd HH:mm:ss.SSS}] " + FIELDS + " %-5p %m%n");
    assertThat(LogPatternInjection.enhance(enhanced, framework, "trace_id", "span_id"))
        .isEqualTo(enhanced);
  }

  @ParameterizedTest
  @ValueSource(ints = {0, 1, 2, 3})
  void literalKeysAndEscapedConvertersDoNotSuppress(int framework) {
    String pattern = "%d trace_id %%X{span_id} service.name %m%n";
    assertThat(LogPatternInjection.enhance(pattern, framework, "trace_id", "span_id"))
        .isEqualTo("%d " + FIELDS + " trace_id %%X{span_id} service.name %m%n");
    assertThat(LogPatternInjection.enhance("%d %X{trace_id} %m", framework, "trace_id", "span_id"))
        .isEqualTo("%d service.name=%X{service.name} span_id=%X{span_id} %X{trace_id} %m");
  }

  @Test
  void frameworkSpecificSyntaxAndWrappers() {
    assertThat(
            LogPatternInjection.enhance(
                "%clr(%d{HH:mm:ss}){blue} %mdc{trace_id:-none} %m", 0, "trace_id", "span_id"))
        .isEqualTo(
            "%clr(%d{HH:mm:ss}){blue} service.name=%X{service.name} span_id=%X{span_id}"
                + " %mdc{trace_id:-none} %m");
    assertThat(LogPatternInjection.enhance("%d %X %m", 0, "trace_id", "span_id"))
        .isEqualTo("%d %X %m");
    assertThat(
            LogPatternInjection.enhance(
                "%d %MDC{service.name, trace_id, span_id} %m", 2, "trace_id", "span_id"))
        .isEqualTo("%d %MDC{service.name, trace_id, span_id} %m");
    assertThat(LogPatternInjection.enhance("%d %mdc{trace_id} %m", 1, "trace_id", "span_id"))
        .isEqualTo("%d " + FIELDS + " %mdc{trace_id} %m");
    assertThat(LogPatternInjection.enhance("%d %X{trace_id} %m", 2, "custom_trace", "custom_span"))
        .contains("custom_trace=%X{custom_trace}", "custom_span=%X{custom_span}");
  }

  @ParameterizedTest
  @ValueSource(strings = {"'trace_id'", " trace_id ", "trace_id,ignored"})
  void recognizesNativeLogbackOptions(String option) {
    assertThat(LogPatternInjection.enhance("%d %X{" + option + "} %m", 0, "trace_id", "span_id"))
        .isEqualTo("%d service.name=%X{service.name} span_id=%X{span_id} %X{" + option + "} %m");
  }

  @Test
  void preservesQuotedDateOptionsAndBraces() {
    String field = "%d{\"yyyy-MM-dd '{'\"}";
    assertThat(LogPatternInjection.enhance(field + " %m", 0, "trace_id", "span_id"))
        .isEqualTo(field + " " + FIELDS + " %m");
  }

  @Test
  void wrapperOptionTextDoesNotCountAsAnMdcConverter() {
    String field = "%replace(%d{HH:mm:ss}){':', '%X{trace_id}'}";
    assertThat(LogPatternInjection.enhance(field + " %m", 0, "trace_id", "span_id"))
        .isEqualTo(field + " " + FIELDS + " %m");
  }

  @Test
  void distinguishesEarlyAndLaterLog4jWholeMdc() {
    assertThat(LogPatternInjection.enhance("%d %X %m", 1, "trace_id", "span_id"))
        .isEqualTo("%d " + FIELDS + " %X %m");
    assertThat(LogPatternInjection.enhance("%d %X %m", 3, "trace_id", "span_id"))
        .isEqualTo("%d %X %m");
  }

  @Test
  void preservesLiteralDatePrefixAndLeadingWhitespace() {
    assertThat(LogPatternInjection.enhance("  timestamp=%d{HH:mm:ss} %m", 0, "trace_id", "span_id"))
        .isEqualTo("  timestamp=%d{HH:mm:ss} " + FIELDS + " %m");
  }

  @Test
  void emptyPatternsAreUnchanged() {
    assertThat(LogPatternInjection.enhance(null, 0, "trace_id", "span_id")).isNull();
    assertThat(LogPatternInjection.enhance("", 0, "trace_id", "span_id")).isEmpty();
  }
}

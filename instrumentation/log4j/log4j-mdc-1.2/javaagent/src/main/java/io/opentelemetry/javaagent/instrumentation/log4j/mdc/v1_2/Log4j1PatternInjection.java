/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.javaagent.instrumentation.log4j.mdc.v1_2;

import org.apache.log4j.spi.LoggingEvent;

public final class Log4j1PatternInjection {
  public static final int FRAMEWORK = framework();

  private static int framework() {
    try {
      // Added in 1.2.16, when the classic PatternParser gained whole-MDC %X support.
      // getProperties itself was already present in 1.2.15, which still requires a key.
      Class.forName(
          "org.apache.log4j.EnhancedPatternLayout", false, LoggingEvent.class.getClassLoader());
      return 3;
    } catch (ClassNotFoundException ignored) {
      return 1;
    }
  }

  private Log4j1PatternInjection() {}
}

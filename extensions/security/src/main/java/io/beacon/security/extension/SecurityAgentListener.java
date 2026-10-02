/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.beacon.security.extension;

import static java.util.logging.Level.WARNING;

import io.beacon.security.core.Settings;
import io.opentelemetry.javaagent.extension.AgentListener;
import io.opentelemetry.sdk.autoconfigure.AutoConfiguredOpenTelemetrySdk;
import java.lang.instrument.Instrumentation;
import java.util.logging.Logger;

public final class SecurityAgentListener implements AgentListener {
  private static final Logger logger = Logger.getLogger(SecurityAgentListener.class.getName());

  @Override
  public void afterAgent(AutoConfiguredOpenTelemetrySdk sdk) {
    if (!Settings.enabled("beacon.security.enabled", false)) {
      return;
    }
    Instrumentation instrumentation = null;
    try {
      // Pinned agent bootstrap API supplies actual loaded classes without triggering class loading.
      Class<?> holder =
          Class.forName(
              "io.opentelemetry.javaagent.bootstrap.InstrumentationHolder",
              false,
              getClass().getClassLoader());
      instrumentation = (Instrumentation) holder.getMethod("getInstrumentation").invoke(null);
    } catch (ReflectiveOperationException error) {
      logger.log(
          WARNING,
          "[BeaconSecurity] loaded-class observation unavailable; SBOM remains deployment inventory: {0}",
          error.getClass().getSimpleName());
    }
    SecurityRuntime.start(instrumentation);
  }
}

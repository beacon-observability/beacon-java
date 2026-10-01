/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.beacon.security.extension;

import io.beacon.security.core.Settings;
import io.opentelemetry.javaagent.extension.AgentListener;
import io.opentelemetry.sdk.autoconfigure.AutoConfiguredOpenTelemetrySdk;
import java.lang.instrument.Instrumentation;

public final class SecurityAgentListener implements AgentListener {
  @Override
  public void afterAgent(AutoConfiguredOpenTelemetrySdk sdk) {
    if (!Settings.enabled("beacon.security.enabled", false)) return;
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
      System.err.println(
          "[BeaconSecurity] loaded-class observation unavailable; SBOM remains deployment inventory");
    }
    SecurityRuntime.start(instrumentation);
  }
}

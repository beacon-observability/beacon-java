/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.instrumentation.profiling.internal;

import io.opentelemetry.instrumentation.profiling.ProfileExporterAdapter;
import io.opentelemetry.instrumentation.profiling.RuntimeProfiling;
import io.opentelemetry.sdk.resources.Resource;
import java.net.URL;
import java.time.Duration;
import java.util.Map;
import jdk.jfr.FlightRecorder;

/**
 * This class is internal and experimental. Its APIs are unstable and can change at any time. Its
 * APIs (or a version of them) may be promoted to the public stable API in the future, but no
 * guarantees are made.
 */
public final class JfrSupport {

  public static RuntimeProfiling build(
      ProfilingConfig config, ProfileExporterAdapter exporterAdapter) {
    if (!isJfrAvailable()) {
      return NoopRuntimeProfiling.INSTANCE;
    }
    return new JfrRuntimeProfiling(config, exporterAdapter);
  }

  public static boolean isJfrAvailable() {
    try {
      return FlightRecorder.isAvailable();
    } catch (Throwable ignored) {
      return false;
    }
  }

  public static ProfileExporterAdapter otlpExporter(
      URL endpoint,
      String protocol,
      Duration timeout,
      Map<String, String> headers,
      Resource resource) {
    return new OtlpProfileExporterAdapter(endpoint, protocol, timeout, headers, resource);
  }

  private JfrSupport() {}
}

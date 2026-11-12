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

/**
 * This class is internal and experimental. Its APIs are unstable and can change at any time. Its
 * APIs (or a version of them) may be promoted to the public stable API in the future, but no
 * guarantees are made.
 */
public final class JfrSupport {

  public static RuntimeProfiling build(
      ProfilingConfig config, ProfileExporterAdapter exporterAdapter) {
    return NoopRuntimeProfiling.INSTANCE;
  }

  public static boolean isJfrAvailable() {
    return false;
  }

  public static ProfileExporterAdapter otlpExporter(
      URL endpoint,
      String protocol,
      Duration timeout,
      Map<String, String> headers,
      Resource resource) {
    throw new UnsupportedOperationException("OTLP profiling requires Java 11+");
  }

  private JfrSupport() {}
}

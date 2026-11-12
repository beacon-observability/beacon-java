/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.javaagent.instrumentation.profiling;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Locale.ROOT;

import io.opentelemetry.sdk.autoconfigure.spi.ConfigProperties;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLDecoder;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.logging.Logger;

final class AgentProfilingConfiguration {

  private static final String PREFIX = "otel.profiling.";
  private static final Logger logger =
      Logger.getLogger(AgentProfilingConfiguration.class.getName());

  private final Duration interval;
  private final Duration startupDelay;
  private final Duration maxAge;
  private final long maxSize;
  private final int stackDepth;
  private final Path tempDir;
  private final String exporter;
  private final boolean memoryEnabled;
  private final Boolean memoryAllocationSampling;
  private final Boolean memoryOldObjectSampling;
  private final Path fileExportPath;
  private final URL otlpEndpoint;
  private final String otlpProtocol;
  private final Duration otlpTimeout;
  private final Map<String, String> otlpHeaders;

  static boolean isEnabled(ConfigProperties config) {
    return defaultBoolean(getBoolean(config, "enabled"), false);
  }

  static AgentProfilingConfiguration create(ConfigProperties config) {
    String exporter = normalizeExporter(defaultString(getString(config, "exporter"), "otlp"));
    if (getInt(config, "stack-depth") != null) {
      logger.warning(
          "Profiling stack-depth cannot configure per-recording JFR stack depth. "
              + "Use JVM -XX:FlightRecorderOptions=stackdepth=<depth> instead; "
              + "this option affects all JFR recordings.");
    }
    return new AgentProfilingConfiguration(
        defaultDuration(getDuration(config, "interval"), Duration.ofMinutes(1)),
        defaultDuration(getDuration(config, "startup-delay"), Duration.ZERO),
        defaultDuration(getDuration(config, "max-age"), Duration.ofMinutes(5)),
        defaultLong(getLong(config, "max-size"), 0),
        defaultInt(getInt(config, "stack-depth"), 64),
        toPath(getString(config, "temp-dir")),
        exporter,
        defaultBoolean(getBoolean(config, "memory.enabled"), false),
        getBoolean(config, "memory.allocation-sampling"),
        getBoolean(config, "memory.old-object-sampling"),
        toPathOrDefault(
            "file".equals(exporter) ? getString(config, "file.path") : null,
            Paths.get(System.getProperty("java.io.tmpdir"), "otel-profiles")),
        otlpEndpoint(config, exporter),
        "otlp".equals(exporter) ? otlpProtocol(config) : "http/protobuf",
        "otlp".equals(exporter) ? otlpTimeout(config) : Duration.ofSeconds(10),
        "otlp".equals(exporter) ? otlpHeaders(config) : Map.of());
  }

  private static URL otlpEndpoint(ConfigProperties config, String exporter) {
    if (!"otlp".equals(exporter)) {
      return toUrlOrDefault(null, "http://localhost:4318/v1development/profiles");
    }
    String protocol = otlpProtocol(config);
    String endpoint = config.getString("otel.exporter.otlp.profiles.endpoint");
    if (endpoint == null) {
      String base = config.getString("otel.exporter.otlp.endpoint");
      endpoint =
          protocol.equals("grpc")
              ? (base == null ? "http://localhost:4317" : base)
              : (base == null ? "http://localhost:4318" : base.replaceAll("/+$", ""))
                  + "/v1development/profiles";
    }
    URL url = toUrlOrDefault(endpoint, "http://localhost:4318/v1development/profiles");
    if (protocol.equals("grpc")
        && ((!url.getPath().isEmpty() && !url.getPath().equals("/"))
            || url.getQuery() != null
            || url.getRef() != null)) {
      throw new IllegalArgumentException(
          "gRPC Profiles endpoint must contain only scheme and host:port");
    }
    return toUrlOrDefault(endpoint, "http://localhost:4318/v1development/profiles");
  }

  private static String otlpProtocol(ConfigProperties config) {
    String value = config.getString("otel.exporter.otlp.profiles.protocol");
    if (value == null) {
      value = config.getString("otel.exporter.otlp.protocol");
    }
    if (value == null) {
      return "http/protobuf";
    }
    if (!value.equals("grpc") && !value.equals("http/protobuf")) {
      throw new IllegalArgumentException("Unsupported OTLP Profiles protocol: " + value);
    }
    return value;
  }

  private static Duration otlpTimeout(ConfigProperties config) {
    Duration value = config.getDuration("otel.exporter.otlp.profiles.timeout");
    if (value == null) {
      value = config.getDuration("otel.exporter.otlp.timeout");
    }
    Duration result = defaultDuration(value, Duration.ofSeconds(10));
    if (result.toMillis() < 1 || result.toMillis() > Integer.MAX_VALUE) {
      throw new IllegalArgumentException("Invalid OTLP Profiles timeout");
    }
    return result;
  }

  private static Map<String, String> otlpHeaders(ConfigProperties config) {
    String value = config.getString("otel.exporter.otlp.profiles.headers");
    if (value == null) {
      value = config.getString("otel.exporter.otlp.headers");
    }
    Map<String, String> headers = new LinkedHashMap<>();
    if (value != null) {
      for (String entry : value.split(",")) {
        int separator = entry.indexOf('=');
        if (separator <= 0) {
          throw new IllegalArgumentException("Invalid OTLP Profiles header");
        }
        headers.put(
            URLDecoder.decode(entry.substring(0, separator).trim().replace("+", "%2B"), UTF_8),
            URLDecoder.decode(entry.substring(separator + 1).trim().replace("+", "%2B"), UTF_8));
      }
    }
    return headers;
  }

  private AgentProfilingConfiguration(
      Duration interval,
      Duration startupDelay,
      Duration maxAge,
      long maxSize,
      int stackDepth,
      Path tempDir,
      String exporter,
      boolean memoryEnabled,
      Boolean memoryAllocationSampling,
      Boolean memoryOldObjectSampling,
      Path fileExportPath,
      URL otlpEndpoint,
      String otlpProtocol,
      Duration otlpTimeout,
      Map<String, String> otlpHeaders) {
    this.interval = interval;
    this.startupDelay = startupDelay;
    this.maxAge = maxAge;
    this.maxSize = maxSize;
    this.stackDepth = stackDepth;
    this.tempDir = tempDir;
    this.exporter = exporter;
    this.memoryEnabled = memoryEnabled;
    this.memoryAllocationSampling = memoryAllocationSampling;
    this.memoryOldObjectSampling = memoryOldObjectSampling;
    this.fileExportPath = fileExportPath;
    this.otlpEndpoint = otlpEndpoint;
    this.otlpProtocol = otlpProtocol;
    this.otlpTimeout = otlpTimeout;
    this.otlpHeaders = otlpHeaders;
  }

  Duration getInterval() {
    return interval;
  }

  Duration getStartupDelay() {
    return startupDelay;
  }

  Duration getMaxAge() {
    return maxAge;
  }

  long getMaxSize() {
    return maxSize;
  }

  int getStackDepth() {
    return stackDepth;
  }

  Path getTempDir() {
    return tempDir;
  }

  String getExporter() {
    return exporter;
  }

  boolean isMemoryEnabled() {
    return memoryEnabled;
  }

  Boolean getMemoryAllocationSampling() {
    return memoryAllocationSampling;
  }

  Boolean getMemoryOldObjectSampling() {
    return memoryOldObjectSampling;
  }

  Path getFileExportPath() {
    return fileExportPath;
  }

  String getOtlpProtocol() {
    return otlpProtocol;
  }

  URL getOtlpEndpoint() {
    return otlpEndpoint;
  }

  Map<String, String> getOtlpHeaders() {
    return otlpHeaders;
  }

  Duration getOtlpTimeout() {
    return otlpTimeout;
  }

  private static Duration defaultDuration(Duration value, Duration defaultValue) {
    return value != null ? value : defaultValue;
  }

  private static boolean defaultBoolean(Boolean value, boolean defaultValue) {
    return value != null ? value : defaultValue;
  }

  private static long defaultLong(Long value, long defaultValue) {
    return value != null ? value : defaultValue;
  }

  private static int defaultInt(Integer value, int defaultValue) {
    return value != null ? value : defaultValue;
  }

  private static String defaultString(String value, String defaultValue) {
    return value != null ? value : defaultValue;
  }

  private static String normalizeExporter(String exporter) {
    String normalized = exporter.trim().toLowerCase(ROOT);
    if (normalized.isEmpty()) {
      return "otlp";
    }
    if (!normalized.equals("file") && !normalized.equals("otlp")) {
      throw new IllegalArgumentException("Unsupported profiling exporter: " + normalized);
    }
    return normalized;
  }

  private static Boolean getBoolean(ConfigProperties config, String suffix) {
    return config.getBoolean(PREFIX + suffix);
  }

  private static Duration getDuration(ConfigProperties config, String suffix) {
    return config.getDuration(PREFIX + suffix);
  }

  private static Integer getInt(ConfigProperties config, String suffix) {
    return config.getInt(PREFIX + suffix);
  }

  private static Long getLong(ConfigProperties config, String suffix) {
    return config.getLong(PREFIX + suffix);
  }

  private static String getString(ConfigProperties config, String suffix) {
    return config.getString(PREFIX + suffix);
  }

  private static Path toPath(String value) {
    return value == null || value.isEmpty() ? null : Paths.get(value);
  }

  private static Path toPathOrDefault(String value, Path defaultValue) {
    return value == null || value.isEmpty() ? defaultValue : Paths.get(value);
  }

  private static URL toUrlOrDefault(String value, String defaultValue) {
    try {
      URL url = new URL(value == null || value.isEmpty() ? defaultValue : value);
      if (!url.getProtocol().equals("http") && !url.getProtocol().equals("https")) {
        throw new IllegalArgumentException("OTLP Profiles requires an HTTP(S) endpoint");
      }
      return url;
    } catch (MalformedURLException exception) {
      throw new IllegalArgumentException("Invalid OTLP Profiles endpoint", exception);
    }
  }
}

/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.beacon.security.core;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Collections.emptyMap;

import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import java.util.UUID;

public final class Identity {
  public static final String VERSION = version();
  public static final String INSTANCE = UUID.randomUUID().toString();
  private static volatile Map<String, String> resource = emptyMap();

  private Identity() {}

  public static void configure(Map<String, String> values) {
    resource = Collections.unmodifiableMap(new LinkedHashMap<>(values));
  }

  public static String applicationId() {
    return "app-"
        + digest(
            resource.getOrDefault("service.namespace", "")
                + "|"
                + resource.getOrDefault(
                    "service.name",
                    Settings.text("otel.service.name", "unknown-java-application")));
  }

  public static Map<String, Object> context() {
    return Values.map(
        "application_id",
        applicationId(),
        "instance_id",
        INSTANCE,
        "service",
        new LinkedHashMap<>(resource),
        "code",
        Values.map(
            "repository",
            resource.getOrDefault("vcs.repository.url.full", ""),
            "commit",
            resource.getOrDefault("vcs.ref.head.revision", ""),
            "build_id",
            "",
            "service_version",
            resource.getOrDefault("service.version", "")),
        "runtime",
        runtime(),
        "identity_status",
        resource.containsKey("service.name") ? "configured" : "fallback");
  }

  public static Map<String, Object> runtime() {
    String os = System.getProperty("os.name", "unknown").toLowerCase(Locale.ROOT);
    if (os.startsWith("windows")) os = "win32";
    else if (os.startsWith("mac")) os = "darwin";
    String arch = System.getProperty("os.arch", "unknown").toLowerCase(Locale.ROOT);
    if (arch.equals("aarch64")) arch = "arm64";
    else if (arch.equals("amd64") || arch.equals("x86_64")) arch = "x64";
    else if (arch.equals("x86") || arch.matches("i[3-6]86")) arch = "ia32";
    return Values.map(
        "language",
        "java",
        "implementation",
        "jvm",
        "version",
        System.getProperty("java.version", ""),
        "os",
        os,
        "architecture",
        arch,
        "details",
        Values.map(
            "vendor",
            System.getProperty("java.vendor", ""),
            "vm_name",
            System.getProperty("java.vm.name", "")));
  }

  private static String version() {
    try (InputStream input =
        Identity.class.getResourceAsStream("/META-INF/beacon/security-version.properties")) {
      if (input != null) {
        Properties properties = new Properties();
        properties.load(input);
        String value = properties.getProperty("version", "").trim();
        if (!value.isEmpty()) return value;
      }
    } catch (IOException ignored) {
      // Development classpaths without processed resources use the explicit fallback below.
    }
    return "development";
  }

  public static String digest(String value) {
    try {
      byte[] bytes = MessageDigest.getInstance("SHA-256").digest(value.getBytes(UTF_8));
      StringBuilder result = new StringBuilder(64);
      for (byte b : bytes) {
        result.append(Character.forDigit((b >>> 4) & 15, 16));
        result.append(Character.forDigit(b & 15, 16));
      }
      return result.toString();
    } catch (NoSuchAlgorithmException error) {
      throw new IllegalStateException(error);
    }
  }
}

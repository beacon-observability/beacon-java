/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.beacon.security.core;

import java.util.Locale;

public final class Settings {
  private Settings() {}

  public static String text(String key, String fallback) {
    String value = System.getProperty(key);
    if (value == null)
      value = System.getenv(key.toUpperCase(Locale.ROOT).replace('.', '_').replace('-', '_'));
    return value == null ? fallback : value;
  }

  public static boolean enabled(String key, boolean fallback) {
    return Boolean.parseBoolean(text(key, Boolean.toString(fallback)));
  }

  public static int limit(String key, int fallback) {
    try {
      int value = Integer.parseInt(text(key, Integer.toString(fallback)));
      return value > 0 ? value : fallback;
    } catch (NumberFormatException ignored) {
      return fallback;
    }
  }
}

/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.beacon.security.core;

import java.util.LinkedHashMap;
import java.util.Map;

public final class Values {
  private Values() {}

  public static Map<String, Object> map(Object... pairs) {
    Map<String, Object> result = new LinkedHashMap<>();
    for (int i = 0; i < pairs.length; i += 2) {
      result.put((String) pairs[i], pairs[i + 1]);
    }
    return result;
  }

  public static String bounded(String value, int maximum) {
    return value == null ? "" : value.substring(0, Math.min(value.length(), maximum));
  }

  public static int length(Object value) {
    if (value instanceof String) {
      return ((String) value).length();
    }
    if (value instanceof StringBuilder) {
      return ((StringBuilder) value).length();
    }
    if (value instanceof StringBuffer) {
      return ((StringBuffer) value).length();
    }
    return -1;
  }
}

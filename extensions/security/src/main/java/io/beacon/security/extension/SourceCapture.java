/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.beacon.security.extension;

import io.beacon.security.core.SecurityState;
import java.io.InputStream;
import java.io.Reader;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.Enumeration;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

final class SourceCapture {
  private SourceCapture() {}

  static void capture(
      SecurityState state, String method, Object name, Object result, String location) {
    String type =
        method.equals("body") || method.equals("getReader") || method.equals("getInputStream")
            ? "http.request.body"
            : method.toLowerCase(Locale.ROOT).contains("header")
                ? "http.request.header"
                : "http.request.parameter";
    String field =
        name instanceof String ? (String) name : method.equals("body") ? "body" : "parameters";
    if (result instanceof Enumeration
        || result instanceof Reader
        || result instanceof InputStream) {
      state.container(result, method, field, location);
      return;
    }
    for (StackTraceElement frame : Thread.currentThread().getStackTrace()) {
      String cls = frame.getClassName();
      if (cls.startsWith("java.")
          || cls.startsWith("javax.")
          || cls.startsWith("jakarta.")
          || cls.startsWith("jdk.")
          || cls.startsWith("sun.")
          || cls.startsWith("io.beacon.security.")
          || cls.startsWith("io.opentelemetry.")
          || cls.startsWith("org.apache.")
          || cls.startsWith("org.springframework.")) {
        continue;
      }
      location =
          cls
              + "#"
              + frame.getMethodName()
              + "("
              + (frame.getFileName() == null ? "" : frame.getFileName())
              + (frame.getLineNumber() < 0 ? "" : ":" + frame.getLineNumber())
              + ")";
      break;
    }
    new Walker(state, type, location).visit(result, field, 0);
  }

  private static final class Walker {
    final SecurityState state;
    final String type;
    final String location;
    final IdentityHashMap<Object, Boolean> visited = new IdentityHashMap<>();
    int count;

    Walker(SecurityState state, String type, String location) {
      this.state = state;
      this.type = type;
      this.location = location;
    }

    void visit(Object value, String name, int depth) {
      if (value == null) {
        return;
      }
      if (depth > 8 || ++count > 512) {
        state.gap("source_traversal_limit");
        return;
      }
      if (visited.put(value, true) != null) {
        return;
      }
      if (value instanceof String) {
        state.source(value, type, name, location);
        return;
      }
      if (value instanceof Object[]) {
        Object[] values = (Object[]) value;
        if (values.length > 128) {
          state.gap("source_traversal_limit");
        }
        for (int i = 0; i < Math.min(values.length, 128); i++) {
          visit(values[i], name + "[" + i + "]", depth + 1);
        }
      } else if (value instanceof Map) {
        int i = 0;
        for (Object item : ((Map<?, ?>) value).entrySet()) {
          if (++i > 128) {
            state.gap("source_traversal_limit");
            break;
          }
          Map.Entry<?, ?> entry = (Map.Entry<?, ?>) item;
          if (entry.getKey() instanceof String) {
            visit(entry.getValue(), name + "." + entry.getKey(), depth + 1);
          }
        }
      } else if (value instanceof List) {
        List<?> values = (List<?>) value;
        if (values.size() > 128) {
          state.gap("source_traversal_limit");
        }
        for (int i = 0; i < Math.min(values.size(), 128); i++) {
          visit(values.get(i), name + "[" + i + "]", depth + 1);
        }
      } else if (type.equals("http.request.body")
          && !value.getClass().getName().startsWith("java.")) {
        for (Class<?> cls = value.getClass();
            cls != null && cls != Object.class;
            cls = cls.getSuperclass()) {
          for (Field field : cls.getDeclaredFields()) {
            if (count >= 512) {
              state.gap("source_traversal_limit");
              return;
            }
            if (Modifier.isStatic(field.getModifiers()) || field.isSynthetic()) {
              continue;
            }
            try {
              field.setAccessible(true);
              visit(field.get(value), name + "." + field.getName(), depth + 1);
            } catch (Exception ignored) {
              state.gap("body_field_inaccessible");
            }
          }
        }
      }
    }
  }
}

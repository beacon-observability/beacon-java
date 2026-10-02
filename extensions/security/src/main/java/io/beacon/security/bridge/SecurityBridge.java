/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.beacon.security.bridge;

import java.util.function.BiFunction;

public final class SecurityBridge {
  private static volatile BiFunction<Integer, Object[], Object> handler;
  private static final Object[] EMPTY = new Object[0];

  private SecurityBridge() {}

  public static void install(BiFunction<Integer, Object[], Object> callback) {
    if (handler == null) {
      handler = callback;
    }
  }

  public static boolean active() {
    try {
      BiFunction<Integer, Object[], Object> callback = handler;
      return callback != null && Boolean.TRUE.equals(callback.apply(3, EMPTY));
    } catch (Throwable ignored) {
      return false;
    }
  }

  public static Object before(
      String owner,
      String method,
      String descriptor,
      Object receiver,
      Object[] args,
      String location,
      Class<?> caller) {
    try {
      BiFunction<Integer, Object[], Object> callback = handler;
      if (!active()) {
        return null;
      }
      return callback == null
          ? null
          : callback.apply(
              0, new Object[] {owner, method, descriptor, receiver, args, location, caller});
    } catch (Throwable ignored) {
      return null;
    }
  }

  public static void after(Object token, Object result) {
    if (token == null) {
      return;
    }
    try {
      Object unused = handler.apply(1, new Object[] {token, result});
    } catch (Throwable ignored) {
      // Instrumentation must never change application behavior.
    }
  }

  public static void constructed(Object result, Object token) {
    after(token, result);
  }

  public static void source(String method, Object name, Object result, String location) {
    try {
      BiFunction<Integer, Object[], Object> callback = handler;
      if (callback != null) {
        Object unused = callback.apply(2, new Object[] {method, name, result, location});
      }
    } catch (Throwable ignored) {
      // Instrumentation must never change application behavior.
    }
  }
}

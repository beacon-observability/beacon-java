/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.beacon.security.core;

import java.util.ArrayList;
import java.util.List;

public final class Propagation {
  private Propagation() {}

  public static void after(Call c, Object result) {
    if (result == null || !c.state.active()) {
      return;
    }
    if (c.owner.equals("java/lang/String") && c.method.equals("substring")) {
      int start = c.integer(0, 0);
      int end = c.integer(1, c.receiverLength);
      c.state.put(result, c.step(c.receiverMarks, -start, start, end, true));
      return;
    }
    if (c.owner.equals("java/lang/String") && c.method.equals("concat")) {
      List<Mark> marks = new ArrayList<>(c.step(c.receiverMarks, 0, 0, Integer.MAX_VALUE, true));
      marks.addAll(c.step(c.arg(0), c.receiverLength, 0, Integer.MAX_VALUE, true));
      c.state.put(result, marks);
      return;
    }
    if (c.owner.equals("java/lang/StringBuilder") || c.owner.equals("java/lang/StringBuffer")) {
      builder(c, result);
      return;
    }
    if (c.owner.equals("java/lang/invoke/StringConcatFactory")) {
      concat(c, result);
      return;
    }
    List<Mark> all = c.allMarks();
    if (all.isEmpty()) {
      return;
    }
    boolean exact =
        c.owner.equals("java/lang/String")
            && (c.method.equals("toString")
                || (c.method.equals("<init>")
                    && c.arguments.length == 1
                    && c.arguments[0] instanceof String));
    c.state.put(result, c.step(all, 0, 0, Integer.MAX_VALUE, exact));
  }

  private static void builder(Call c, Object result) {
    List<Mark> marks;
    if (c.method.equals("toString")) {
      c.state.put(result, c.step(c.receiverMarks, 0, 0, c.receiverLength, true));
      return;
    }
    if (c.method.equals("setLength")) {
      c.state.put(result, c.step(c.receiverMarks, 0, 0, c.integer(0, 0), true));
      return;
    }
    if (c.method.equals("<init>")) {
      boolean exact = c.arguments.length == 1 && c.arguments[0] instanceof String;
      c.state.put(result, c.step(c.arg(0), 0, 0, Integer.MAX_VALUE, exact));
      return;
    }
    if (c.method.equals("append")) {
      marks = new ArrayList<>(c.step(c.receiverMarks, 0, 0, Integer.MAX_VALUE, true));
      boolean exact = c.arguments.length > 0 && c.arguments[0] instanceof String;
      int from = c.arguments.length == 3 ? c.integer(1, 0) : 0;
      int to = c.arguments.length == 3 ? c.integer(2, Integer.MAX_VALUE) : Integer.MAX_VALUE;
      marks.addAll(c.step(c.arg(0), c.receiverLength - from, from, to, exact));
    } else {
      marks = c.step(c.allMarks(), 0, 0, Integer.MAX_VALUE, false);
    }
    c.state.put(result, marks);
  }

  private static void concat(Call c, Object result) {
    // Recipe literals and String arguments have known widths. Never invoke an application's
    // toString twice.
    String recipe = c.descriptor;
    int argument = 0;
    int offset = 0;
    boolean exact = true;
    List<Mark> output = new ArrayList<>();
    for (int i = 0; i < recipe.length(); i++) {
      char ch = recipe.charAt(i);
      if (ch == '\u0002' && i + 1 < recipe.length()) {
        i++;
        offset++;
        continue;
      }
      if (ch != '\u0001') {
        offset++;
        continue;
      }
      if (argument >= c.arguments.length) {
        exact = false;
        break;
      }
      Object value = c.arguments[argument];
      output.addAll(c.step(c.arg(argument), offset, 0, Integer.MAX_VALUE, exact));
      if (value == null) {
        offset += 4;
      } else if (value instanceof String) {
        offset += ((String) value).length();
      } else if (value instanceof Byte
          || value instanceof Short
          || value instanceof Integer
          || value instanceof Long
          || value instanceof Float
          || value instanceof Double
          || value instanceof Boolean
          || value instanceof Character) {
        offset += String.valueOf(value).length();
      } else {
        exact = false;
      }
      argument++;
    }
    c.state.put(result, output);
  }
}

/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.beacon.security.core;

import static java.util.Collections.emptyList;

import java.util.ArrayList;
import java.util.IdentityHashMap;
import java.util.List;

public final class Call {
  public final SecurityState state;
  public final String owner;
  public final String method;
  public final String descriptor;
  public final Object receiver;
  public final Object[] arguments;
  public final String location;
  public final List<Mark> receiverMarks;
  public final List<List<Mark>> argumentMarks = new ArrayList<>();
  public final int receiverLength;

  public Call(
      SecurityState state,
      String owner,
      String method,
      String descriptor,
      Object receiver,
      Object[] arguments,
      String location) {
    this.state = state;
    this.owner = owner;
    this.method = method;
    this.descriptor = descriptor;
    this.receiver = receiver;
    this.arguments = arguments;
    this.location = location;
    receiverMarks = state.marks(receiver);
    receiverLength = Values.length(receiver);
    int[] remaining = {512};
    for (Object arg : arguments) {
      List<Mark> marks = new ArrayList<>();
      // Each argument needs its own marks even when argument identities repeat.
      collect(state, arg, 0, marks, new IdentityHashMap<Object, Integer>(), remaining);
      argumentMarks.add(marks);
    }
  }

  private static void collect(
      SecurityState state,
      Object value,
      int depth,
      List<Mark> marks,
      IdentityHashMap<Object, Integer> visited,
      int[] remaining) {
    if (marks.size() >= 64) {
      state.gap("call_input_mark_limit");
      return;
    }
    if (remaining[0]-- <= 0) {
      state.gap("call_input_traversal_limit");
      return;
    }
    Integer previousDepth = visited.get(value);
    if (previousDepth != null && previousDepth <= depth) {
      return;
    }
    visited.put(value, depth);
    if (previousDepth == null) {
      for (Mark mark : state.marks(value)) {
        if (marks.size() >= 64) {
          state.gap("call_input_mark_limit");
          break;
        }
        marks.add(mark);
      }
    }
    if (value instanceof Object[]) {
      Object[] values = (Object[]) value;
      if (values.length == 0) {
        return;
      }
      if (depth >= 3 || values.length > 128) {
        state.gap("call_input_traversal_limit");
      }
      if (depth >= 3) {
        return;
      }
      for (int i = 0; i < Math.min(values.length, 128) && marks.size() < 64; i++) {
        if (remaining[0] <= 0) {
          state.gap("call_input_traversal_limit");
          break;
        }
        collect(state, values[i], depth + 1, marks, visited, remaining);
      }
    }
  }

  public List<Mark> allMarks() {
    List<Mark> marks = new ArrayList<>(receiverMarks);
    for (List<Mark> part : argumentMarks) {
      marks.addAll(part);
    }
    return marks;
  }

  public List<Mark> arg(int index) {
    return index < argumentMarks.size() ? argumentMarks.get(index) : emptyList();
  }

  public int integer(int index, int fallback) {
    return index < arguments.length && arguments[index] instanceof Integer
        ? (Integer) arguments[index]
        : fallback;
  }

  public List<Mark> step(List<Mark> marks, int shift, int from, int to, boolean exact) {
    return state.step(
        marks, owner.replace('/', '.') + "." + method, location, shift, from, to, exact);
  }
}

/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.beacon.security.core;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.junit.jupiter.api.Test;

class PreciseStringPropagationTest {
  @Test
  void trimAndSubsequencePreserveOffsetsAndExactness() {
    try (SecurityState state = new SecurityState()) {
      String input = new String("  guest  ");
      state.source(input, "http.parameter", "value", "fixture:source");
      Call trim =
          new Call(state, "java/lang/String", "trim", "()", input, new Object[0], "fixture:trim");
      String trimmed = input.trim();
      Propagation.after(trim, trimmed);
      List<Mark> marks = state.marks(trimmed);
      assertThat(marks).hasSize(1);
      assertThat(marks.get(0).exact).isTrue();
      assertThat(marks.get(0).start).isZero();
      assertThat(marks.get(0).end).isEqualTo(5);
      Call subsequence =
          new Call(
              state,
              "java/lang/String",
              "subSequence",
              "()",
              trimmed,
              new Object[] {1, 4},
              "fixture:subsequence");
      String result = trimmed.subSequence(1, 4).toString();
      Propagation.after(subsequence, result);
      assertThat(state.marks(result).get(0).end).isEqualTo(3);
      assertThat(state.marks(result).get(0).exact).isTrue();
    }
  }

  @Test
  void characterReplacementPreservesTaintInsteadOfTreatingItAsSanitization() {
    try (SecurityState state = new SecurityState()) {
      String input = new String("a'b");
      state.source(input, "http.parameter", "value", "fixture:source");
      Call call =
          new Call(
              state,
              "java/lang/String",
              "replace",
              "(CC)",
              input,
              new Object[] {'\'', '_'},
              "fixture:replace");
      String result = input.replace('\'', '_');
      Propagation.after(call, result);
      assertThat(state.marks(result)).hasSize(1);
      assertThat(state.marks(result).get(0).exact).isTrue();
      assertThat(state.marks(result).get(0).end).isEqualTo(result.length());
    }
  }
}

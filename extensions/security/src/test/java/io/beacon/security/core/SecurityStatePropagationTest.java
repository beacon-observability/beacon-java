/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.beacon.security.core;

import static java.util.Collections.singleton;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.junit.jupiter.api.Test;

class SecurityStatePropagationTest {
  @Test
  void callTraversalBoundsCyclesAndKeepsSharedArgumentMarks() {
    SecurityState state = new SecurityState();
    try {
      String source = new String("shared-input");
      state.source(source, "parameter", "q", "test");
      Object[] cycle = new Object[128];
      Arrays.fill(cycle, cycle);
      cycle[127] = source;
      Call shared = new Call(state, "test", "call", "", null, new Object[] {cycle, cycle}, "test");
      assertEquals(1, shared.arg(0).size());
      assertEquals(1, shared.arg(1).size());
      Object[] wide = new Object[128];
      for (int i = 0; i < wide.length; i++) {
        Object[] row = new Object[128];
        for (int j = 0; j < row.length; j++) {
          row[j] = new Object();
        }
        wide[i] = row;
      }
      new Call(state, "test", "call", "", null, new Object[] {wide}, "test");
      assertTrue(state.gaps().contains("call_input_traversal_limit"));
    } finally {
      state.close();
    }
  }

  @Test
  void trackingBytesRejectLargeResultsAndAreReleasedOnClose() {
    String requestLimit = System.getProperty("beacon.security.max.tracked.bytes");
    System.setProperty("beacon.security.max.tracked.bytes", "4096");
    SecurityState first = new SecurityState();
    SecurityState third = new SecurityState();
    String input = new String(new char[500]);
    String other = new String(new char[500]);
    try {
      first.source(input, "parameter", "q", "test");
      assertFalse(first.marks(input).isEmpty());
      first.source(other, "parameter", "other", "test");
      assertTrue(first.marks(other).isEmpty());
      assertTrue(first.truncated());
      first.close();
      first.close();
      assertEquals(0, first.trackedBytes());
      third.source(input, "parameter", "q", "test");
      assertFalse(third.marks(input).isEmpty());
      String large = input.concat(new String(new char[10000]));
      Propagation.after(
          new Call(third, "java/lang/String", "concat", "", input, new Object[] {large}, "test"),
          large);
      assertTrue(third.marks(large).isEmpty());
      assertTrue(third.truncated());
      assertTrue(third.trackedBytes() <= 4096);
    } finally {
      first.close();
      third.close();
      if (requestLimit == null) {
        System.clearProperty("beacon.security.max.tracked.bytes");
      } else {
        System.setProperty("beacon.security.max.tracked.bytes", requestLimit);
      }
    }
  }

  @Test
  void sourceIdentityDoesNotLeakToEqualString() {
    SecurityState state = new SecurityState();
    String source = new String("same-value");
    String equalButDifferentObject = new String("same-value");

    state.source(source, "http.parameter", "value", "fixture:1");

    assertFalse(state.marks(source).isEmpty());
    assertTrue(state.marks(equalButDifferentObject).isEmpty());
    assertEquals(1, state.trackedObjects());
  }

  @Test
  void substringPreservesExactOutputRange() {
    SecurityState state = new SecurityState();
    String source = new String("abcdef");
    state.source(source, "http.parameter", "value", "fixture:2");

    String result = source.substring(1, 4);
    Call call =
        new Call(
            state,
            "java/lang/String",
            "substring",
            "(II)Ljava/lang/String;",
            source,
            new Object[] {1, 4},
            "fixture:3");
    Propagation.after(call, result);

    List<Mark> marks = state.marks(result);
    assertEquals(1, marks.size());
    assertTrue(marks.get(0).exact);
    assertEquals(0, marks.get(0).start);
    assertEquals(3, marks.get(0).end);
  }

  @Test
  void concatAndBuilderKeepBothInputObjects() {
    SecurityState state = new SecurityState();
    String first = new String("left");
    String second = new String("right");
    state.source(first, "http.parameter", "first", "fixture:4");
    state.source(second, "http.header", "second", "fixture:5");

    String concatenated = first.concat(second);
    Propagation.after(
        new Call(
            state,
            "java/lang/String",
            "concat",
            "(Ljava/lang/String;)Ljava/lang/String;",
            first,
            new Object[] {second},
            "fixture:6"),
        concatenated);
    assertEquals(2, state.marks(concatenated).size());

    StringBuilder builder = new StringBuilder(first);
    Propagation.after(
        new Call(
            state,
            "java/lang/StringBuilder",
            "<init>",
            "(Ljava/lang/String;)V",
            builder,
            new Object[] {first},
            "fixture:7"),
        builder);
    Call append =
        new Call(
            state,
            "java/lang/StringBuilder",
            "append",
            "(Ljava/lang/String;)Ljava/lang/StringBuilder;",
            builder,
            new Object[] {second},
            "fixture:8");
    builder.append(second);
    Propagation.after(append, builder);
    String built = builder.toString();
    Propagation.after(
        new Call(
            state,
            "java/lang/StringBuilder",
            "toString",
            "()Ljava/lang/String;",
            builder,
            new Object[0],
            "fixture:9"),
        built);
    assertEquals(2, state.marks(built).size());
  }

  @Test
  void constantBuilderPrefixDoesNotDropLaterSource() {
    SecurityState state = new SecurityState();
    String source = new String("request-value");
    state.source(source, "http.parameter", "value", "fixture:constant-prefix");

    StringBuilder builder = new StringBuilder("constant:");
    Propagation.after(
        new Call(
            state,
            "java/lang/StringBuilder",
            "<init>",
            "(Ljava/lang/String;)V",
            builder,
            new Object[] {"constant:"},
            "fixture:constant-prefix"),
        builder);
    Call append =
        new Call(
            state,
            "java/lang/StringBuilder",
            "append",
            "(Ljava/lang/String;)Ljava/lang/StringBuilder;",
            builder,
            new Object[] {source},
            "fixture:constant-prefix");
    builder.append(source);
    Propagation.after(append, builder);

    String result = builder.toString();
    Propagation.after(
        new Call(
            state,
            "java/lang/StringBuilder",
            "toString",
            "()Ljava/lang/String;",
            builder,
            new Object[0],
            "fixture:constant-prefix"),
        result);
    assertEquals(1, state.marks(result).size());
    assertEquals("http.parameter", state.marks(result).get(0).node.source.get("type"));
  }

  @Test
  void invokedynamicRecipeMapsArgumentsWithoutCallingToStringAgain() {
    SecurityState state = new SecurityState();
    String first = new String("left");
    String second = new String("right");
    state.source(first, "http.parameter", "first", "fixture:10");
    state.source(second, "http.parameter", "second", "fixture:11");

    String result = first + ":" + second;
    Call call =
        new Call(
            state,
            "java/lang/invoke/StringConcatFactory",
            "makeConcatWithConstants",
            "\u0001:\u0001",
            null,
            new Object[] {first, second},
            "fixture:12");
    Propagation.after(call, result);

    List<Mark> marks = state.marks(result);
    assertEquals(2, marks.size());
    assertEquals(0, marks.get(0).start);
    assertEquals(4, marks.get(0).end);
    assertEquals(5, marks.get(1).start);
    assertEquals(10, marks.get(1).end);
  }

  @Test
  void indyCustomNumberDoesNotCallToStringAndKeepsConservativeMark() {
    SecurityState state = new SecurityState();
    String source = new String("left");
    state.source(source, "http.parameter", "value", "fixture:custom-number");
    CountingNumber number = new CountingNumber();

    String result = "left:custom-number:left";
    Propagation.after(
        new Call(
            state,
            "java/lang/invoke/StringConcatFactory",
            "makeConcatWithConstants",
            "\u0001:\u0001:\u0001",
            null,
            new Object[] {source, number, source},
            "fixture:custom-number"),
        result);

    assertEquals(0, number.toStringCalls);
    assertEquals(2, state.marks(result).size());
    assertTrue(state.marks(result).get(0).exact);
    assertEquals(0, state.marks(result).get(0).start);
    assertEquals(4, state.marks(result).get(0).end);
    assertFalse(state.marks(result).get(1).exact);
    assertEquals(result.length(), state.marks(result).get(1).end);
  }

  @Test
  void evidenceIsBoundedAndDeduplicated() {
    SecurityState state = new SecurityState();
    String source = new String("input");
    state.source(source, "http.parameter", "value", "fixture:13");
    state.traceId = "11111111111111111111111111111111";
    state.serverSpanId = "2222222222222222";

    Map<String, Object> evidence =
        state.evidence(
            "sql",
            "query",
            "Statement.execute",
            "fixture:14",
            state.marks(source),
            "3333333333333333");
    assertNotNull(evidence);
    assertEquals("beacon.security.finding", evidence.get("event_name"));
    assertEquals(Events.FINGERPRINT_VERSION, evidence.get("fingerprint_version"));
    assertEquals("11111111111111111111111111111111", evidence.get("trace_id"));
    assertEquals("3333333333333333", evidence.get("current_span_id"));
    assertNull(
        state.evidence(
            "sql",
            "query",
            "Statement.execute",
            "fixture:14",
            state.marks(source),
            "3333333333333333"));
    assertEquals(1, state.evidenceIds().size());
  }

  @Test
  void candidateFindingIdentityIsStableAcrossRequestStates() {
    SecurityState first = new SecurityState();
    String firstValue = new String("same-request-shape");
    first.source(firstValue, "http.parameter", "value", "fixture:finding-source");
    Map<String, Object> firstEvidence =
        first.evidence(
            "sql_injection",
            "query",
            "Statement.executeQuery",
            "fixture:finding-site",
            first.marks(firstValue),
            "span-first");

    SecurityState second = new SecurityState();
    String secondValue = new String("different-request-value");
    second.source(secondValue, "http.parameter", "value", "fixture:finding-source");
    Map<String, Object> secondEvidence =
        second.evidence(
            "sql_injection",
            "query",
            "Statement.executeQuery",
            "fixture:finding-site",
            second.marks(secondValue),
            "span-second");

    assertNotNull(firstEvidence);
    assertNotNull(secondEvidence);
    assertEquals(firstEvidence.get("finding_id"), secondEvidence.get("finding_id"));
    assertEquals("candidate_risk", firstEvidence.get("assessment"));
    assertEquals("unvalidated", firstEvidence.get("validation"));
    assertFalse("confirmed".equals(firstEvidence.get("assessment")));
  }

  @Test
  void oneObjectBudgetCoversAllSourceCarriers() {
    String previous = System.getProperty("beacon.security.max.tracked.bytes");
    System.setProperty("beacon.security.max.tracked.bytes", "16777216");
    try (SecurityState state = new SecurityState()) {
      List<String> sources = new ArrayList<>();
      List<URL> urls = new ArrayList<>();
      List<Enumeration<String>> enumerations = new ArrayList<>();
      for (int i = 0; i < 1366; i++) {
        String source = new String("source-" + i);
        sources.add(source);
        state.source(source, "http.parameter", "value[" + i + "]", "fixture:budget");
      }
      for (int i = 0; i < 1365; i++) {
        try {
          URL url = new URL("http://127.0.0.1/" + i);
          urls.add(url);
          state.container(url, "URL.create", "url", "fixture:budget");
        } catch (MalformedURLException error) {
          throw new AssertionError(error);
        }
      }
      for (int i = 0; i < 1365; i++) {
        Enumeration<String> enumeration = Collections.enumeration(singleton("header-" + i));
        enumerations.add(enumeration);
        state.container(enumeration, "Enumeration", "header", "fixture:budget");
      }

      assertEquals(4096, state.trackedObjects());
      assertEquals(1365, enumerations.size());
      assertFalse(state.truncated());
      state.destination(urls.get(0), "component-ref");
      assertEquals("component-ref", state.destination(urls.get(0)));

      String extraSource = new String("source-extra");
      state.source(extraSource, "http.parameter", "extra", "fixture:budget");
      URL extraUrl;
      try {
        extraUrl = new URL("http://127.0.0.1/extra");
      } catch (MalformedURLException error) {
        throw new AssertionError(error);
      }
      Enumeration<String> extraEnumeration = Collections.enumeration(singleton("header-extra"));
      state.container(extraUrl, "URL.create", "extra", "fixture:budget");
      state.container(extraEnumeration, "Enumeration", "extra", "fixture:budget");

      assertTrue(state.truncated());
      assertTrue(state.marks(extraSource).isEmpty());
      assertNull(state.container(extraUrl));
      assertNull(state.container(extraEnumeration));
      Map<?, ?> counts = (Map<?, ?>) state.diagnostics().get("counts");
      assertEquals(4096, ((Number) counts.get("objects")).intValue());
      assertEquals(1366, sources.size());
    } finally {
      if (previous == null) {
        System.clearProperty("beacon.security.max.tracked.bytes");
      } else {
        System.setProperty("beacon.security.max.tracked.bytes", previous);
      }
    }
  }

  @Test
  void equalValuesInConcurrentStatesStayIdentityIsolated() throws Exception {
    SecurityState first = new SecurityState();
    SecurityState second = new SecurityState();
    String firstValue = new String("same-value");
    String secondValue = new String("same-value");
    ExecutorService executor = Executors.newFixedThreadPool(2);
    try {
      Future<?> firstTask =
          executor.submit(
              () -> first.source(firstValue, "http.parameter", "first", "fixture:parallel"));
      Future<?> secondTask =
          executor.submit(
              () -> second.source(secondValue, "http.parameter", "second", "fixture:parallel"));
      firstTask.get();
      secondTask.get();
    } finally {
      executor.shutdownNow();
    }

    assertFalse(first.marks(firstValue).isEmpty());
    assertTrue(first.marks(secondValue).isEmpty());
    assertFalse(second.marks(secondValue).isEmpty());
    assertTrue(second.marks(firstValue).isEmpty());
  }

  @Test
  void closeReleasesObjectAndDestinationState() {
    SecurityState state = new SecurityState();
    String source = new String("input");
    state.source(source, "http.parameter", "value", "fixture:15");
    state.destination(source, "component-ref");

    state.close();

    assertFalse(state.active());
    assertTrue(state.marks(source).isEmpty());
    assertNull(state.destination(source));
    assertNull(
        state.evidence(
            "sql", "query", "Statement.execute", "fixture:16", state.marks(source), "span"));
  }

  private static final class CountingNumber extends Number {
    private int toStringCalls;

    @Override
    public int intValue() {
      return 1;
    }

    @Override
    public long longValue() {
      return 1L;
    }

    @Override
    public float floatValue() {
      return 1.0f;
    }

    @Override
    public double doubleValue() {
      return 1.0d;
    }

    @Override
    public String toString() {
      toStringCalls++;
      return "custom-number";
    }
  }
}

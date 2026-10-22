/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.beacon.security.extension;

import static java.util.Arrays.asList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.params.provider.Arguments.argumentSet;

import io.beacon.security.core.AttackEvidence;
import io.beacon.security.core.Call;
import io.beacon.security.core.SecurityState;
import io.beacon.security.core.StackFrames;
import java.lang.reflect.Proxy;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import sample.calls.CallSiteFixture;

class SinkCoverageTest {
  @ParameterizedTest
  @MethodSource("fileCalls")
  void commonFileApisCaptureThePath(String owner, String method) {
    try (SecurityState state = new SecurityState()) {
      String path = new String("/tmp/controlled-file");
      state.source(path, "http.parameter", "path", "fixture:path");
      List<SinkRules.Finding> findings = new ArrayList<>();
      assertThat(CallSites.matches(owner, method)).isTrue();
      SinkRules.before(call(state, owner, method, null, path), findings::add);
      assertThat(findings).hasSize(1);
      assertThat(findings.get(0).marks).isNotEmpty();
      assertThat(findings.get(0).rule).isEqualTo("path_traversal");
    }
  }

  private static Stream<Arguments> fileCalls() {
    return Stream.of(
        argumentSet("reader", "java/io/FileReader", "<init>"),
        argumentSet("writer", "java/io/FileWriter", "<init>"),
        argumentSet("print writer", "java/io/PrintWriter", "<init>"),
        argumentSet("lines", "java/nio/file/Files", "lines"),
        argumentSet("list", "java/nio/file/Files", "list"),
        argumentSet("walk", "java/nio/file/Files", "walk"),
        argumentSet("exists", "java/nio/file/Files", "exists"),
        argumentSet("create", "java/nio/file/Files", "createFile"));
  }

  @Test
  void batchesKeepStatementEvidenceSeparateAndClearTheirTracking() {
    Object statement = statement();
    try (SecurityState state = new SecurityState()) {
      String input = new String("controlled SQL");
      state.source(input, "http.parameter", "query", "fixture:sql");
      state.addBatch(
          statement, state.marks(input), AttackEvidence.suspected("tainted_sql_structure"));
      for (String method : asList("executeBatch", "executeLargeBatch")) {
        assertThat(CallSites.matches("java/sql/Statement", method)).isTrue();
        List<SinkRules.Finding> findings = new ArrayList<>();
        SinkRules.before(
            new Call(
                state,
                "java/sql/Statement",
                method,
                "()",
                statement,
                new Object[0],
                "fixture:batch"),
            findings::add);
        assertThat(findings).hasSize(1);
        assertThat(findings.get(0).marks).isNotEmpty();
        assertThat(findings.get(0).attackEvidence.fields().get("status")).isEqualTo("suspected");
      }
      state.clearBatch(statement);
      assertThat(state.batchInputs(statement)).isEmpty();
      assertThat(state.marks(statement)).isEmpty();
    }
  }

  @Test
  void executeLargeUpdateClassifiesItsActualSql() {
    try (SecurityState state = new SecurityState()) {
      String sql = new String("SELECT 1");
      state.source(sql, "http.parameter", "query", "fixture:sql");
      List<SinkRules.Finding> findings = new ArrayList<>();
      SinkRules.before(
          call(state, "java/sql/Statement", "executeLargeUpdate", statement(), sql), findings::add);
      assertThat(findings).hasSize(1);
      assertThat(findings.get(0).marks).isNotEmpty();
    }
  }

  @Test
  void unavailableProxyFrameDoesNotHideTheFollowingBusinessLocation() {
    try (SecurityState state = new SecurityState()) {
      Call call =
          new Call(
              state,
              "driver/Statement",
              "execute",
              "()",
              statement(),
              new Object[0],
              "driver#execute");
      List<StackFrames.Frame> frames =
          asList(
              new StackFrames.Frame(
                  new StackTraceElement("missing.Proxy", "execute", "Proxy.java", 3), null),
              new StackFrames.Frame(
                  new StackTraceElement(
                      CallSiteFixture.class.getName(), "construct", "CallSiteFixture.java", 20),
                  null));
      assertThat(SecurityRuntime.logicalSite(call, getClass().getClassLoader(), frames))
          .isEqualTo("sample.calls.CallSiteFixture#construct(CallSiteFixture.java:20)");
    }
  }

  @Test
  void httpsOwnerIsMatchedAtBothLayers() {
    assertThat(CallSites.matches("javax/net/ssl/HttpsURLConnection", "getInputStream")).isTrue();
    assertThat(SinkRules.isHttpSink("javax/net/ssl/HttpsURLConnection", "getInputStream")).isTrue();
  }

  private static Object statement() {
    return Proxy.newProxyInstance(
        SinkCoverageTest.class.getClassLoader(),
        new Class<?>[] {Statement.class},
        (proxy, method, args) -> null);
  }

  private static Call call(
      SecurityState state, String owner, String method, Object receiver, String input) {
    return new Call(state, owner, method, "()", receiver, new Object[] {input}, "fixture:sink");
  }
}

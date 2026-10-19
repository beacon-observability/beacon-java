/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.beacon.security.extension;

import static java.util.Collections.singletonList;
import static org.assertj.core.api.Assertions.assertThat;

import io.beacon.security.core.Call;
import io.beacon.security.core.Mark;
import io.beacon.security.core.SecurityState;
import java.lang.reflect.Proxy;
import java.sql.PreparedStatement;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class AttackAnalysisTest {
  private String previousDialect;

  @BeforeEach
  void setDialect() {
    previousDialect = System.getProperty("beacon.security.analysis.sql.dialect");
    System.setProperty("beacon.security.analysis.sql.dialect", "ansi");
  }

  @AfterEach
  void restoreDialect() {
    if (previousDialect == null) {
      System.clearProperty("beacon.security.analysis.sql.dialect");
    } else {
      System.setProperty("beacon.security.analysis.sql.dialect", previousDialect);
    }
  }

  @ParameterizedTest
  @MethodSource("sqlCases")
  void classifiesSqlContext(String text, String input, String status) {
    try (SecurityState state = new SecurityState()) {
      assertThat(AttackAnalysis.sql(text, marks(state, text, input)).fields())
          .containsEntry("status", status)
          .containsEntry("outcome", "not_assessed");
    }
  }

  private static Stream<Arguments> sqlCases() {
    return Stream.of(
        Arguments.of("SELECT * FROM users WHERE name='guest'", "guest", "no_evidence"),
        Arguments.of(
            "SELECT * FROM users WHERE name='OR UNION SELECT'", "OR UNION SELECT", "no_evidence"),
        Arguments.of("SELECT * FROM users WHERE name='O''Reilly'", "O''Reilly", "no_evidence"),
        Arguments.of("SELECT * FROM users WHERE name='O'Reilly'", "O'Reilly", "unknown"),
        Arguments.of("SELECT * FROM users WHERE name='' OR '1'='1'", "' OR '1'='1", "suspected"),
        Arguments.of("SELECT * FROM users WHERE id=1 OR 1=1", "1 OR 1=1", "suspected"),
        Arguments.of("SELECT * FROM users WHERE id=-12", "-12", "no_evidence"),
        Arguments.of("SELECT * FROM users WHERE id=12.5", "12.5", "no_evidence"),
        Arguments.of("SELECT * FROM users WHERE id=1-1", "1-1", "suspected"),
        Arguments.of("SELECT * FROM users WHERE id=1 + 1", "1 + 1", "suspected"),
        Arguments.of("SELECT * FROM users WHERE id=1.2.3", "1.2.3", "unknown"),
        Arguments.of("SELECT name FROM users", "name", "unknown"),
        Arguments.of("SELECT * FROM users WHERE name=$$guest$$", "guest", "unknown"),
        Arguments.of("SELECT * FROM users WHERE name='a\\'b'", "a\\'b", "unknown"),
        Arguments.of(
            "SELECT * FROM users WHERE id=1; DELETE FROM users",
            "1; DELETE FROM users",
            "suspected"),
        Arguments.of("SELECT * FROM users WHERE id=1 /*", "1 /*", "unknown"));
  }

  @ParameterizedTest
  @MethodSource("shellCases")
  void classifiesShellContext(String text, String input, String status) {
    try (SecurityState state = new SecurityState()) {
      assertThat(AttackAnalysis.shell("sh", text, marks(state, text, input)).fields())
          .containsEntry("status", status)
          .containsEntry("outcome", "not_assessed");
    }
  }

  private static Stream<Arguments> shellCases() {
    return Stream.of(
        Arguments.of("echo guest", "guest", "no_evidence"),
        Arguments.of("echo if", "if", "no_evidence"),
        Arguments.of("if test guest; then echo ok; fi", "guest", "unknown"),
        Arguments.of("echo 'a;b'", "a;b", "no_evidence"),
        Arguments.of("echo \"a;b\"", "a;b", "no_evidence"),
        Arguments.of("echo a\\;b", "a\\;b", "no_evidence"),
        Arguments.of("echo guest; id", "guest; id", "suspected"),
        Arguments.of("echo 'guest'; id; echo ''", "guest'; id; echo '", "suspected"),
        Arguments.of("echo 'unclosed", "unclosed", "unknown"),
        Arguments.of("echo $(id)", "$(id)", "unknown"),
        Arguments.of("echo '${name}'", "${name}", "no_evidence"),
        Arguments.of("echo name > output", "name", "unknown"));
  }

  @Test
  void unknownDialectImprecisionAndBudgetsNeverBecomeSafe() {
    try (SecurityState state = new SecurityState()) {
      String text = "SELECT 'guest'";
      List<Mark> marks = marks(state, text, "guest");
      System.setProperty("beacon.security.analysis.sql.dialect", "unknown");
      assertThat(AttackAnalysis.sql(text, marks).fields()).containsEntry("status", "unknown");
      System.setProperty("beacon.security.analysis.sql.dialect", "ansi");
      Mark mark = marks.get(0);
      assertThat(
              AttackAnalysis.sql(
                      text, singletonList(new Mark(mark.node, mark.start, mark.end, false)))
                  .fields())
          .containsEntry("reason", "taint_imprecise");
      String large = new String(new char[AttackAnalysis.MAX_LENGTH + 1]).replace('\0', 'x');
      assertThat(AttackAnalysis.sql(large, marks).fields())
          .containsEntry("reason", "analysis_budget");
      assertThat(AttackAnalysis.shell("cmd.exe", "guest", marks).fields())
          .containsEntry("reason", "shell_dialect_unsupported");
      assertThat(AttackAnalysis.sql(null, marks).fields())
          .containsEntry("reason", "input_unavailable");
    }
  }

  @Test
  void preparedTemplateEvidenceIsIndependentOfBoundParameters() {
    Object statement =
        Proxy.newProxyInstance(
            getClass().getClassLoader(),
            new Class<?>[] {PreparedStatement.class},
            (proxy, method, args) -> null);
    try (SecurityState state = new SecurityState()) {
      List<SinkRules.Finding> findings = new ArrayList<>();
      SinkRules.before(
          new Call(
              state,
              "java/sql/PreparedStatement",
              "executeQuery",
              "()",
              statement,
              new Object[0],
              "fixture:sql"),
          findings::add);
      assertThat(findings.get(0).marks).isEmpty();
      String sql = "SELECT * FROM users WHERE id=1 OR 1=1";
      List<Mark> marks = marks(state, sql, "1 OR 1=1");
      state.put(statement, marks);
      state.preparedEvidence(statement, AttackAnalysis.sql(sql, marks));
      findings.clear();
      SinkRules.before(
          new Call(
              state,
              "java/sql/PreparedStatement",
              "executeQuery",
              "()",
              statement,
              new Object[0],
              "fixture:sql"),
          findings::add);
      assertThat(findings.get(0).marks).isNotEmpty();
      assertThat(findings.get(0).attackEvidence.fields()).containsEntry("status", "suspected");
    }
  }

  @Test
  void missingBoundaryPoliciesRemainUnknownAndFixedHostQueryIsNotAnAttack() {
    try (SecurityState state = new SecurityState()) {
      String path = new String("/allowed/file.txt");
      state.source(path, "http.parameter", "file", "fixture:source");
      List<SinkRules.Finding> findings = new ArrayList<>();
      SinkRules.before(
          new Call(
              state,
              "java/nio/file/Files",
              "readAllBytes",
              "()",
              null,
              new Object[] {path},
              "fixture:file"),
          findings::add);
      assertThat(findings.get(0).attackEvidence.fields())
          .containsEntry("status", "unknown")
          .containsEntry("reason", "boundary_policy_unavailable");
      String url = new String("https://fixed.example/?q=guest");
      state.put(url, marks(state, url, "guest"));
      findings.clear();
      SinkRules.before(
          new Call(
              state,
              "org/springframework/web/client/RestTemplate",
              "execute",
              "()",
              null,
              new Object[] {url},
              "fixture:http"),
          findings::add);
      assertThat(findings.get(0).rule).isEqualTo("http_request_input");
      assertThat(findings.get(0).attackEvidence.fields()).containsEntry("status", "no_evidence");
      state.source(url, "http.parameter", "url", "fixture:source");
      String target = new String("http://127.0.0.1/");
      state.source(target, "http.parameter", "url", "fixture:source");
      findings.clear();
      SinkRules.before(
          new Call(
              state,
              "org/springframework/web/client/RestTemplate",
              "execute",
              "()",
              null,
              new Object[] {target},
              "fixture:http"),
          findings::add);
      assertThat(findings.get(0).rule).isEqualTo("ssrf");
      assertThat(findings.get(0).attackEvidence.fields()).containsEntry("status", "unknown");
    }
  }

  private static List<Mark> marks(SecurityState state, String text, String input) {
    String source = new String(input);
    state.source(source, "http.parameter", "value", "fixture:source");
    Mark mark = state.marks(source).get(0);
    int start = text.indexOf(input);
    return singletonList(new Mark(mark.node, start, start + input.length(), true));
  }
}

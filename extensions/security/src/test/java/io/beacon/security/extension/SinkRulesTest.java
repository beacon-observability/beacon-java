/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.beacon.security.extension;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Arrays.asList;
import static java.util.Collections.singletonList;
import static java.util.concurrent.TimeUnit.SECONDS;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.beacon.security.core.Call;
import io.beacon.security.core.Mark;
import io.beacon.security.core.SecurityState;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class SinkRulesTest {
  @TempDir Path temp;

  @Test
  void restTemplateUsesOnlyDestinationMarksAndPreservesQueryRoles() {
    String owner = "org/springframework/web/client/RestTemplate";
    String url = new String("http://127.0.0.1:8080/target");
    List<SinkRules.Finding> raw =
        classify(
            marked(url, "fixture:url"),
            owner,
            "execute",
            null,
            new Object[] {url, String.class, new Object[0]});
    assertMarkedFinding(raw, "destination_address", "full URL controls the destination");

    String query = new String("http://fixed.example/target?q=controlled");
    List<SinkRules.Finding> queryOnly =
        classify(
            markedToken(query, "controlled", "fixture:query"),
            "org/springframework/web/client/RestOperations",
            "execute",
            null,
            new Object[] {query, String.class, new Object[0]});
    assertEquals(1, queryOnly.size());
    assertEquals("http_request_input", queryOnly.get(0).rule);
    assertMarkedFinding(queryOnly, "path_or_query", "query must not taint the fixed host");

    String body = new String("controlled body");
    List<SinkRules.Finding> bodyOnly =
        classify(
            marked(body, "fixture:body"),
            owner,
            "execute",
            null,
            new Object[] {url, body, String.class, new Object[0]});
    assertTrue(bodyOnly.stream().allMatch(finding -> finding.marks.isEmpty()));
  }

  @Test
  void runtimeExecArrayRecognizesCombinedPosixOptionsAndRunsTheMarkedScript() throws Exception {
    for (String option : asList("-lc", "-ec", "-xc")) {
      String script = new String("printf '%s' BEACON_SECURITY_MARKER_" + option.substring(1, 2));
      SecurityState state = marked(script, "fixture:shell:" + option);
      String[] command = {"bash", option, script};
      List<SinkRules.Finding> findings =
          classify(state, "java/lang/Runtime", "exec", null, new Object[] {command});

      ProcessResult process = run(Runtime.getRuntime().exec(command));
      assertEquals(0, process.exitCode, option);
      assertEquals("BEACON_SECURITY_MARKER_" + option.substring(1, 2), process.stdout, option);
      assertMarkedFinding(findings, "shell_command", option);
    }
  }

  @Test
  void combinedOptionWithValueSkipsTheValueBeforeTheCommand() throws Exception {
    String script = new String("printf '%s' BEACON_SECURITY_MARKER_LCO");
    SecurityState state = marked(script, "fixture:shell:lco");
    String[] command = {"bash", "-lco", "posix", script};
    List<SinkRules.Finding> findings =
        classify(state, "java/lang/Runtime", "exec", null, new Object[] {command});

    ProcessResult process = run(Runtime.getRuntime().exec(command));
    assertEquals(0, process.exitCode);
    assertEquals("BEACON_SECURITY_MARKER_LCO", process.stdout);
    assertMarkedFinding(findings, "shell_command", "-lco must skip the -o value");
  }

  @Test
  void shellScriptKeepsZeroAndOneArgumentsAsOrdinaryArguments() throws Exception {
    String script = new String("printf '%s:%s' \"$0\" \"$1\"");
    SecurityState state = marked(script, "fixture:shell:argv");
    String[] command = {"bash", "-c", script, "ARG_ZERO", "ARG_ONE"};
    List<SinkRules.Finding> findings =
        classify(state, "java/lang/Runtime", "exec", null, new Object[] {command});

    ProcessResult process = run(Runtime.getRuntime().exec(command));
    assertEquals(0, process.exitCode);
    assertEquals("ARG_ZERO:ARG_ONE", process.stdout);
    assertMarkedFinding(findings, "shell_command", "script must be a shell command");
    List<SinkRules.Finding> ordinary = findingsForRole(findings, "ordinary_argument");
    assertEquals(3, ordinary.size(), "-c and the two shell argv values stay ordinary");
    for (SinkRules.Finding finding : ordinary) {
      assertTrue(finding.marks.isEmpty());
    }
  }

  @Test
  void scriptFileMakesLaterCAnOrdinaryScriptArgumentForProcessBuilder() throws Exception {
    Path scriptFile = temp.resolve("safe-script.sh");
    Files.write(scriptFile, singletonList("printf '%s' FILE_BEACON_SECURITY_MARKER"), UTF_8);
    String scriptPath = new String(scriptFile.toString());
    String payload = new String("printf '%s' SHOULD_NOT_RUN");
    SecurityState state = marked(scriptPath, "fixture:shell:file");
    ProcessBuilder builder = new ProcessBuilder("bash", scriptPath, "-c", payload, "ARG_ZERO");
    List<SinkRules.Finding> findings =
        classify(state, "java/lang/ProcessBuilder", "start", builder, new Object[0]);

    ProcessResult process = run(builder.start());
    assertEquals(0, process.exitCode);
    assertEquals("FILE_BEACON_SECURITY_MARKER", process.stdout);
    assertTrue(
        findingsForRole(findings, "shell_command").isEmpty(),
        "-c after a script filename is not the shell's command option");
    assertMarkedFinding(
        findings, "ordinary_argument", "script filename remains an ordinary argument");
  }

  @Test
  void optionSentinelsDependOnWhetherCWasAlreadySeen() throws Exception {
    for (String[] command :
        new String[][] {
          {"bash", "-lc", "--", "printf '%s' DOUBLE_DASH_MARKER"},
          {"bash", "-c", "-", "printf '%s' SINGLE_DASH_MARKER"}
        }) {
      String script = command[3];
      SecurityState state = marked(script, "fixture:shell:sentinel-positive");
      List<SinkRules.Finding> findings =
          classify(state, "java/lang/Runtime", "exec", null, new Object[] {command});
      ProcessResult process = run(Runtime.getRuntime().exec(command));
      assertEquals(0, process.exitCode, Arrays.toString(command));
      assertTrue(process.stdout.endsWith("_MARKER"), Arrays.toString(command));
      assertMarkedFinding(findings, "shell_command", Arrays.toString(command));
    }

    Path scriptFile = temp.resolve("sentinel-script.sh");
    Files.write(scriptFile, singletonList("printf '%s' SENTINEL_FILE_MARKER"), UTF_8);
    String scriptPath = new String(scriptFile.toString());
    String payload = new String("printf '%s' SHOULD_NOT_RUN");

    String[] doubleDashFile = {"bash", "--", scriptPath, "-c", payload};
    SecurityState doubleDashState = marked(scriptPath, "fixture:shell:sentinel-file");
    List<SinkRules.Finding> doubleDashFindings =
        classify(doubleDashState, "java/lang/Runtime", "exec", null, new Object[] {doubleDashFile});
    ProcessResult doubleDashProcess = run(Runtime.getRuntime().exec(doubleDashFile));
    assertEquals(0, doubleDashProcess.exitCode);
    assertEquals("SENTINEL_FILE_MARKER", doubleDashProcess.stdout);
    assertTrue(findingsForRole(doubleDashFindings, "shell_command").isEmpty());
    assertAnyMarkedFinding(
        doubleDashFindings, "ordinary_argument", "script filename after -- is ordinary");

    String[] singleDashFile = {"bash", "-", scriptPath, "-c", payload};
    SecurityState singleDashState = marked(scriptPath, "fixture:shell:sentinel-stdin");
    List<SinkRules.Finding> singleDashFindings =
        classify(singleDashState, "java/lang/Runtime", "exec", null, new Object[] {singleDashFile});
    ProcessResult singleDashProcess = run(new ProcessBuilder(singleDashFile).start());
    assertEquals(0, singleDashProcess.exitCode);
    assertEquals("SENTINEL_FILE_MARKER", singleDashProcess.stdout);
    assertTrue(findingsForRole(singleDashFindings, "shell_command").isEmpty());
    assertAnyMarkedFinding(
        singleDashFindings, "ordinary_argument", "script identity after - is an argv value");
  }

  @Test
  void runtimeExecStringAndProcessBuilderUseTheSameShellClassification() throws Exception {
    // Runtime.exec(String) tokenizes on whitespace, so keep the shell script one token
    // and let the shell expand IFS into the printf arguments.
    for (String optionAndValue : asList("-lc", "-lco posix")) {
      String script = new String("printf${IFS}%s${IFS}STRING_BEACON_SECURITY_MARKER");
      String commandLine = new String("bash " + optionAndValue + " " + script);
      SecurityState runtimeState = markedToken(commandLine, script, "fixture:shell:string");
      List<SinkRules.Finding> runtimeFindings =
          classify(runtimeState, "java/lang/Runtime", "exec", null, new Object[] {commandLine});
      ProcessResult runtimeProcess = run(Runtime.getRuntime().exec(commandLine));
      assertEquals(0, runtimeProcess.exitCode, optionAndValue);
      assertEquals("STRING_BEACON_SECURITY_MARKER", runtimeProcess.stdout, optionAndValue);
      assertMarkedFinding(
          runtimeFindings, "shell_command", "Runtime.exec(String) " + optionAndValue);
    }

    String script = new String("printf '%s' PROCESS_BUILDER_BEACON_SECURITY_MARKER");
    SecurityState builderState = marked(script, "fixture:shell:builder");
    ProcessBuilder builder = new ProcessBuilder("bash", "-lc", script);
    List<SinkRules.Finding> builderFindings =
        classify(builderState, "java/lang/ProcessBuilder", "start", builder, new Object[0]);
    ProcessResult builderProcess = run(builder.start());
    assertEquals(0, builderProcess.exitCode);
    assertEquals("PROCESS_BUILDER_BEACON_SECURITY_MARKER", builderProcess.stdout);
    assertMarkedFinding(builderFindings, "shell_command", "ProcessBuilder.start()");
  }

  private static SecurityState marked(String value, String location) {
    SecurityState state = new SecurityState();
    state.source(value, "http.parameter", "command", location);
    return state;
  }

  private static SecurityState markedToken(String commandLine, String token, String location) {
    SecurityState state = marked(token, location);
    int offset = commandLine.indexOf(token);
    List<Mark> tokenMarks =
        state.step(
            state.marks(token), "fixture:command", location, offset, 0, token.length(), true);
    state.put(commandLine, tokenMarks);
    return state;
  }

  private static List<SinkRules.Finding> classify(
      SecurityState state, String owner, String method, Object receiver, Object[] arguments) {
    List<SinkRules.Finding> findings = new ArrayList<>();
    Call call =
        new Call(
            state, owner, method, "fixture:command", receiver, arguments, "fixture:sink-rules");
    SinkRules.before(call, findings::add);
    return findings;
  }

  private static void assertMarkedFinding(
      List<SinkRules.Finding> findings, String role, String message) {
    SinkRules.Finding finding =
        findings.stream().filter(value -> role.equals(value.role)).findFirst().orElse(null);
    assertNotNull(finding, message + ": missing role " + role);
    assertFalse(finding.marks.isEmpty(), message + ": role has no tainted marker");
  }

  private static void assertAnyMarkedFinding(
      List<SinkRules.Finding> findings, String role, String message) {
    assertTrue(
        findings.stream()
            .filter(value -> role.equals(value.role))
            .anyMatch(value -> !value.marks.isEmpty()),
        message + ": no marked finding for role " + role);
  }

  private static List<SinkRules.Finding> findingsForRole(
      List<SinkRules.Finding> findings, String role) {
    List<SinkRules.Finding> result = new ArrayList<>();
    for (SinkRules.Finding finding : findings) {
      if (role.equals(finding.role)) {
        result.add(finding);
      }
    }
    return result;
  }

  private static ProcessResult run(Process process) throws Exception {
    if (!process.waitFor(5, SECONDS)) {
      process.destroyForcibly();
      throw new AssertionError("child process did not finish within five seconds");
    }
    return new ProcessResult(
        process.exitValue(), read(process.getInputStream()), read(process.getErrorStream()));
  }

  private static String read(InputStream stream) throws IOException {
    ByteArrayOutputStream bytes = new ByteArrayOutputStream();
    byte[] buffer = new byte[256];
    int count;
    while ((count = stream.read(buffer)) >= 0) {
      bytes.write(buffer, 0, count);
    }
    return new String(bytes.toByteArray(), UTF_8).trim();
  }

  private static final class ProcessResult {
    final int exitCode;
    final String stdout;
    final String stderr;

    ProcessResult(int exitCode, String stdout, String stderr) {
      this.exitCode = exitCode;
      this.stdout = stdout;
      this.stderr = stderr;
    }

    @Override
    public String toString() {
      return "exitCode=" + exitCode + ", stdout=" + stdout + ", stderr=" + stderr;
    }
  }
}

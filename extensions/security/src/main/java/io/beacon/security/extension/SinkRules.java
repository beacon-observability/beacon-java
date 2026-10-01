/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.beacon.security.extension;

import static java.util.Arrays.asList;

import io.beacon.security.core.Call;
import io.beacon.security.core.Mark;
import java.net.URI;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.StringTokenizer;
import java.util.function.Consumer;

final class SinkRules {
  private SinkRules() {}

  static final class Finding {
    final String rule;
    final String role;
    final List<Mark> marks;

    Finding(String rule, String role, List<Mark> marks) {
      this.rule = rule;
      this.role = role;
      this.marks = marks;
    }
  }

  static void before(Call c, Consumer<Finding> emit) {
    String owner = c.owner;
    String method = c.method;
    if (c.receiver instanceof Statement
        && (method.equals("execute")
            || method.equals("executeQuery")
            || method.equals("executeUpdate"))) {
      emit.accept(
          new Finding(
              "sql_injection",
              "sql_template",
              c.arguments.length > 0 && c.arguments[0] instanceof String
                  ? c.arg(0)
                  : c.receiverMarks));
      return;
    }
    if ((owner.equals("java/lang/Runtime") && method.equals("exec"))
        || (owner.equals("java/lang/ProcessBuilder") && method.equals("start"))) {
      command(c, emit);
      return;
    }
    if (isFileSink(owner, method)) {
      if (c.arguments.length > 0) emit.accept(new Finding("path_traversal", "file_path", c.arg(0)));
      if (method.equals("copy") || method.equals("move"))
        emit.accept(new Finding("path_traversal", "destination_path", c.arg(1)));
      return;
    }
    if (isHttpSink(owner, method)) {
      boolean restTemplate = CallSites.isRestTemplateCall(owner, method);
      List<Mark> marks = restTemplate ? c.arg(0) : c.allMarks();
      if (restTemplate
          && (c.arguments.length == 0
              || !(c.arguments[0] instanceof String || c.arguments[0] instanceof URI))) {
        c.state.gap("rest_template_request_entity_unmodeled");
        return;
      }
      if (restTemplate
          && c.arguments[0] instanceof String
          && ((String) c.arguments[0]).indexOf('{') >= 0)
        c.state.gap("rest_template_uri_template_unmodeled");
      if (marks.isEmpty()) {
        emit.accept(new Finding("ssrf", "destination_unknown", marks));
        emit.accept(new Finding("http_request_input", "path_or_query", marks));
        return;
      }
      String destination = c.state.destination(c.receiver);
      if (restTemplate) {
        Object target = c.arguments[0];
        destination = target instanceof String ? (String) target : target.toString();
      } else {
        for (Object arg : c.arguments)
          if (c.state.destination(arg) != null) {
            destination = c.state.destination(arg);
            break;
          }
      }
      String role = "destination_unknown";
      if (destination != null) {
        int scheme = destination.indexOf("://");
        int end = destination.length();
        if (scheme >= 0) {
          for (int i = scheme + 3; i < destination.length(); i++) {
            char ch = destination.charAt(i);
            if (ch == '/' || ch == '?' || ch == '#') {
              end = i;
              break;
            }
          }
          boolean unknownAddress = false;
          boolean address = false;
          for (Mark mark : marks) {
            boolean overlap = mark.start < end && mark.end > 0;
            address |= overlap;
            unknownAddress |= overlap && !mark.exact;
          }
          role =
              !address
                  ? "path_or_query"
                  : unknownAddress ? "destination_unknown" : "destination_address";
        }
      }
      emit.accept(
          new Finding(role.equals("path_or_query") ? "http_request_input" : "ssrf", role, marks));
    }
  }

  static boolean isFileSink(String owner, String method) {
    if ((owner.equals("java/io/FileInputStream")
            || owner.equals("java/io/FileOutputStream")
            || owner.equals("java/io/RandomAccessFile"))
        && method.equals("<init>")) return true;
    return owner.equals("java/nio/file/Files")
        && (method.startsWith("read")
            || method.startsWith("write")
            || method.startsWith("new")
            || method.startsWith("delete")
            || method.equals("copy")
            || method.equals("move"));
  }

  static boolean isHttpSink(String owner, String method) {
    if (CallSites.isRestTemplateCall(owner, method)) return true;
    if (owner.startsWith("java/net/") && owner.contains("URLConnection"))
      return method.equals("connect")
          || method.equals("getInputStream")
          || method.equals("getOutputStream")
          || method.equals("getResponseCode");
    if (owner.equals("java/net/URL"))
      return method.equals("openStream") || method.equals("getContent");
    if (owner.startsWith("java/net/http/"))
      return method.equals("send") || method.equals("sendAsync");
    if (owner.startsWith("okhttp3/")) return method.equals("execute") || method.equals("enqueue");
    return (owner.startsWith("org/apache/http/") || owner.startsWith("org/apache/hc/"))
        && method.startsWith("execute");
  }

  private static void command(Call c, Consumer<Finding> emit) {
    List<String> args;
    boolean flat = false;
    if (c.receiver instanceof ProcessBuilder) args = ((ProcessBuilder) c.receiver).command();
    else if (c.arguments.length > 0 && c.arguments[0] instanceof String[])
      args = asList((String[]) c.arguments[0]);
    else if (c.arguments.length > 0 && c.arguments[0] instanceof String) {
      String input = (String) c.arguments[0];
      args = new ArrayList<>();
      StringTokenizer tokens = new StringTokenizer(input);
      while (tokens.hasMoreTokens() && args.size() < 128) args.add(tokens.nextToken());
      flat = true;
    } else return;
    if (args.isEmpty()) return;
    String executable = args.get(0).replace('\\', '/');
    executable = executable.substring(executable.lastIndexOf('/') + 1).toLowerCase(Locale.ROOT);
    int shellIndex = shellCommandIndex(executable, args);
    if (flat) {
      String input = (String) c.arguments[0];
      int token = 0;
      int offset = 0;
      List<Mark> executableMarks = new ArrayList<>();
      List<Mark> scriptMarks = new ArrayList<>();
      List<Mark> argumentMarks = new ArrayList<>();
      while (offset < input.length() && token < 128) {
        while (offset < input.length() && " \t\n\r\f".indexOf(input.charAt(offset)) >= 0) offset++;
        int from = offset;
        while (offset < input.length() && " \t\n\r\f".indexOf(input.charAt(offset)) < 0) offset++;
        if (from == offset) break;
        List<Mark> target =
            token == 0
                ? executableMarks
                : shellIndex >= 0
                        && (token == shellIndex || (commandTail(executable) && token > shellIndex))
                    ? scriptMarks
                    : argumentMarks;
        for (Mark mark : c.arg(0))
          if (mark.start < offset && mark.end > from && !target.contains(mark)) target.add(mark);
        token++;
      }
      emit.accept(new Finding("command_execution", "executable", executableMarks));
      emit.accept(new Finding("command_injection", "shell_command", scriptMarks));
      emit.accept(new Finding("command_execution", "ordinary_argument", argumentMarks));
    } else {
      for (int i = 0; i < Math.min(args.size(), 128); i++) {
        String role =
            i == 0
                ? "executable"
                : shellIndex >= 0
                        && (i == shellIndex || (commandTail(executable) && i > shellIndex))
                    ? "shell_command"
                    : "ordinary_argument";
        emit.accept(
            new Finding(
                role.equals("shell_command") ? "command_injection" : "command_execution",
                role,
                c.state.marks(args.get(i))));
      }
    }
  }

  private static int shellCommandIndex(String executable, List<String> args) {
    if (asList("sh", "bash", "dash", "zsh", "ksh").contains(executable)) {
      boolean command = false;
      for (int i = 1; i < args.size(); i++) {
        String option = args.get(i);
        if (option.equals("--") || option.equals("-"))
          return command && i + 1 < args.size() ? i + 1 : -1;
        // The first non-option is command text only if -c was already parsed;
        // otherwise it is a script filename and later -c tokens belong to that script.
        if (option.equals("+") || !(option.startsWith("-") || option.startsWith("+")))
          return command ? i : -1;
        if (option.startsWith("--")) {
          if (option.equals("--rcfile")
              || option.equals("--init-file")
              || option.equals("--emulate")) i++;
          continue;
        }
        if (option.charAt(0) == '-' && option.indexOf('c', 1) >= 0) command = true;
        for (int flag = 1; flag < option.length(); flag++) {
          char value = option.charAt(flag);
          if ((value == 'o' || value == 'O')
              && i + 1 < args.size()
              && !(args.get(i + 1).startsWith("-") || args.get(i + 1).startsWith("+"))) i++;
        }
      }
    } else if (commandTail(executable)) {
      for (int i = 1; i < args.size() - 1; i++) {
        String option = args.get(i).toLowerCase(Locale.ROOT);
        if (option.equals("/c") || option.equals("-c") || option.equals("-command")) return i + 1;
      }
    }
    return -1;
  }

  private static boolean commandTail(String executable) {
    return asList("cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh").contains(executable);
  }
}

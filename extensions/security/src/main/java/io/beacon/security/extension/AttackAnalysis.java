/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.beacon.security.extension;

import io.beacon.security.core.AttackEvidence;
import io.beacon.security.core.Mark;
import io.beacon.security.core.Settings;
import java.util.List;
import javax.annotation.Nullable;

/** Bounded lexical evidence analysis. It neither executes input nor establishes exploit success. */
final class AttackAnalysis {
  static final int MAX_LENGTH = 8192;

  static AttackEvidence sql(@Nullable String text, List<Mark> marks) {
    if (!Settings.text("beacon.security.analysis.sql.dialect", "unknown").equals("ansi")) {
      return AttackEvidence.unknown("sql_dialect_unsupported");
    }
    AttackEvidence unavailable = unavailable(text, marks);
    if (unavailable != null) {
      return unavailable;
    }
    if (text == null) {
      return AttackEvidence.unknown("input_unavailable");
    }
    return scan(text, marks, false);
  }

  static AttackEvidence shell(String executable, String text, List<Mark> marks) {
    if (!(executable.equals("sh")
        || executable.equals("bash")
        || executable.equals("dash")
        || executable.equals("ksh")
        || executable.equals("zsh"))) {
      return AttackEvidence.unknown("shell_dialect_unsupported");
    }
    AttackEvidence unavailable = unavailable(text, marks);
    if (unavailable != null) {
      return unavailable;
    }
    return scan(text, marks, true);
  }

  @Nullable
  private static AttackEvidence unavailable(@Nullable String text, List<Mark> marks) {
    if (text == null) {
      return AttackEvidence.unknown("input_unavailable");
    }
    if (text.length() > MAX_LENGTH || marks.size() > 64) {
      return AttackEvidence.unknown("analysis_budget");
    }
    if (marks.isEmpty()) {
      return AttackEvidence.unknown("taint_unavailable");
    }
    for (Mark mark : marks) {
      if (!mark.exact || mark.start < 0 || mark.end > text.length() || mark.start >= mark.end) {
        return AttackEvidence.unknown("taint_imprecise");
      }
    }
    return null;
  }

  private static AttackEvidence scan(String text, List<Mark> marks, boolean shell) {
    boolean[] tainted = new boolean[text.length()];
    for (Mark mark : marks) {
      for (int i = mark.start; i < mark.end; i++) {
        tainted[i] = true;
      }
    }
    char quote = 0;
    boolean suspected = false;
    boolean identifier = false;
    boolean commandStart = true;
    int parentheses = 0;
    for (int i = 0; i < text.length(); i++) {
      char ch = text.charAt(i);
      char next = i + 1 < text.length() ? text.charAt(i + 1) : 0;
      if (ch == 0 || (Character.isISOControl(ch) && ch != '\n' && ch != '\r' && ch != '\t')) {
        return AttackEvidence.unknown("syntax_unsupported");
      }
      if (shell && ch == '\\' && quote != '\'') {
        if (++i >= text.length()) {
          return AttackEvidence.unknown("syntax_incomplete");
        }
        // In double quotes POSIX backslash only quotes these characters.
        if (quote == '"' && "$`\"\\\n".indexOf(text.charAt(i)) < 0) {
          i--;
        }
        continue;
      }
      if (shell && quote != '\'' && (ch == '$' || ch == '`')) {
        return AttackEvidence.unknown("shell_expansion_unsupported");
      }
      if (!shell && (ch == '\\' || ch == '$' || ch == '`' || ch == '[' || ch == ']')) {
        return AttackEvidence.unknown("sql_syntax_unsupported");
      }
      if (quote != 0) {
        if (ch == quote) {
          if (!shell && next == quote) {
            i++;
          } else {
            // A tainted delimiter can escape a trusted literal without introducing '=' or ';'.
            // Escaped SQL quote pairs above remain data; incomplete syntax still degrades below.
            suspected |= !shell && quote == '\'' && tainted[i];
            quote = 0;
          }
        } else if (!shell && quote == '"' && tainted[i]) {
          identifier = true;
        }
        continue;
      }
      if (ch == '\'' || ch == '"') {
        suspected |= !shell && ch == '\'' && tainted[i];
        commandStart = false;
        quote = ch;
        continue;
      }
      if (shell) {
        if ("(){}<>".indexOf(ch) >= 0) {
          return AttackEvidence.unknown("shell_syntax_unsupported");
        }
        if (ch == '#' && (i == 0 || Character.isWhitespace(text.charAt(i - 1)))) {
          while (i < text.length() && text.charAt(i) != '\n') {
            i++;
          }
          i--;
          continue;
        }
        if (";|&\n".indexOf(ch) >= 0) {
          suspected |= tainted[i];
          commandStart = true;
        } else if (commandStart && !Character.isWhitespace(ch)) {
          int end = i;
          while (end < text.length() && Character.isLetter(text.charAt(end))) {
            end++;
          }
          String word = text.substring(i, end);
          if (word.equals("if")
              || word.equals("then")
              || word.equals("else")
              || word.equals("elif")
              || word.equals("fi")
              || word.equals("for")
              || word.equals("while")
              || word.equals("until")
              || word.equals("case")
              || word.equals("esac")
              || word.equals("do")
              || word.equals("done")
              || word.equals("function")) {
            return AttackEvidence.unknown("shell_syntax_unsupported");
          }
          commandStart = false;
        }
      } else {
        if ((ch == '-' && next == '-') || (ch == '/' && next == '*')) {
          suspected |= tainted[i] || tainted[i + 1];
          if (ch == '-') {
            while (i < text.length() && text.charAt(i) != '\n') {
              i++;
            }
          } else {
            int end = text.indexOf("*/", i + 2);
            if (end < 0) {
              return AttackEvidence.unknown("syntax_incomplete");
            }
            if (text.substring(i + 2, end).contains("/*")) {
              return AttackEvidence.unknown("sql_syntax_unsupported");
            }
            i = end + 1;
          }
          continue;
        }
        if (ch == '(') {
          parentheses++;
        } else if (ch == ')' && --parentheses < 0) {
          return AttackEvidence.unknown("syntax_incomplete");
        }
        if (Character.isDigit(ch)
            || ((ch == '-' || ch == '+') && Character.isDigit(next) && numericSign(text, i))) {
          // A tainted number (including its sign) alone is not syntax injection evidence.
          boolean decimal = false;
          while (i + 1 < text.length()
              && (Character.isDigit(text.charAt(i + 1)) || text.charAt(i + 1) == '.')) {
            i++;
            if (text.charAt(i) == '.') {
              if (decimal) {
                return AttackEvidence.unknown("sql_syntax_unsupported");
              }
              decimal = true;
            }
          }
          continue;
        }
        if (Character.isLetter(ch) || ch == '_') {
          do {
            identifier |= tainted[i];
            i++;
          } while (i < text.length()
              && (Character.isLetterOrDigit(text.charAt(i)) || text.charAt(i) == '_'));
          i--;
          continue;
        }
        if ("=<>!;|&+-*/(),.?".indexOf(ch) < 0 && !Character.isWhitespace(ch)) {
          return AttackEvidence.unknown("sql_syntax_unsupported");
        }
        if (tainted[i] && "=<>!;|&+-*/(),".indexOf(ch) >= 0) {
          suspected = true;
        }
      }
    }
    if (quote != 0 || parentheses != 0) {
      return AttackEvidence.unknown("syntax_incomplete");
    }
    if (suspected) {
      return AttackEvidence.suspected(shell ? "tainted_shell_control" : "tainted_sql_structure");
    }
    return identifier
        ? AttackEvidence.unknown("sql_identifier_control")
        : AttackEvidence.none(shell ? "shell_data_only" : "sql_data_only");
  }

  private static boolean numericSign(String text, int offset) {
    int previous = offset - 1;
    while (previous >= 0 && Character.isWhitespace(text.charAt(previous))) {
      previous--;
    }
    return previous < 0 || "=<>(,".indexOf(text.charAt(previous)) >= 0;
  }

  private AttackAnalysis() {}
}

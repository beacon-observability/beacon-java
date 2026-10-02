/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.beacon.security.extension;

import static java.util.Collections.emptyList;

import io.beacon.security.core.Call;
import io.beacon.security.core.Events;
import io.beacon.security.core.Mark;
import io.beacon.security.core.Propagation;
import io.beacon.security.core.SecurityState;
import io.beacon.security.core.Settings;
import io.beacon.security.core.Values;
import io.beacon.security.exporter.EvidenceExporter;
import io.beacon.security.sbom.SbomInventory;
import io.opentelemetry.api.trace.Span;
import io.opentelemetry.context.Context;
import io.opentelemetry.context.ContextKey;
import java.lang.instrument.Instrumentation;
import java.lang.reflect.InvocationHandler;
import java.net.URI;
import java.net.URL;
import java.sql.Connection;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.BiFunction;

public final class SecurityRuntime {
  static final ContextKey<SecurityState> STATE = ContextKey.named("BeaconSecurity-state");
  private static final ThreadLocal<Boolean> GUARD = new ThreadLocal<>();
  private static final EvidenceExporter EXPORTER = new EvidenceExporter();
  private static volatile SbomInventory inventory;

  private SecurityRuntime() {}

  static void start(Instrumentation instrumentation) {
    if (Settings.enabled("beacon.security.sbom.enabled", true)) {
      inventory =
          new SbomInventory(
              instrumentation,
              event -> {
                EXPORTER.emit(event, Context.root(), false);
                if ("beacon.security.sbom.snapshot".equals(event.get("event_name"))
                    || "beacon.security.sbom.health".equals(event.get("event_name"))
                    || "beacon.security.sbom.update_failed".equals(event.get("event_name"))) {
                  EXPORTER.ledger().sbom(event);
                }
              },
              SecurityConfiguration.applicationIdentity);
      inventory.start();
    } else {
      EXPORTER.ledger().sbom(Values.map("status", "disabled"));
    }
    Runtime.getRuntime()
        .addShutdownHook(
            new Thread(
                () -> {
                  SbomInventory current = inventory;
                  if (current != null) {
                    current.close();
                  }
                  EXPORTER.close();
                },
                "BeaconSecurity-shutdown"));
  }

  static BiFunction<Integer, Object[], Object> handler(ClassLoader loader) {
    return (operation, values) -> {
      if (Boolean.TRUE.equals(GUARD.get())) {
        return null;
      }
      if (operation == 3) {
        SecurityState state = Context.current().get(STATE);
        return state != null
            && state.active()
            && state.collectionEnabled
            && EXPORTER.ledger().enabled();
      }
      GUARD.set(true);
      try {
        if (operation == 0) {
          SecurityState state = Context.current().get(STATE);
          if (state == null
              || !state.active()
              || !state.collectionEnabled
              || !EXPORTER.ledger().enabled()) {
            return null;
          }
          Call call =
              new Call(
                  state,
                  (String) values[0],
                  (String) values[1],
                  (String) values[2],
                  values[3],
                  (Object[]) values[4],
                  (String) values[5]);
          ClassLoader callerLoader =
              values.length > 6 && values[6] instanceof Class
                  ? ((Class<?>) values[6]).getClassLoader()
                  : loader;
          SinkRules.before(call, finding -> emit(call, finding, callerLoader));
          return call;
        }
        if (operation == 1) {
          if (EXPORTER.ledger().enabled()) {
            after((Call) values[0], values[1]);
          }
          return null;
        }
        if (operation == 2) {
          SecurityState state = Context.current().get(STATE);
          if (state != null
              && state.active()
              && state.collectionEnabled
              && EXPORTER.ledger().enabled()) {
            SourceCapture.capture(
                state, (String) values[0], values[1], values[2], (String) values[3]);
          }
        }
        return null;
      } catch (Throwable error) {
        SecurityState state = Context.current().get(STATE);
        if (state != null) {
          state.gap("collection_error:" + error.getClass().getSimpleName());
        }
        return null;
      } finally {
        GUARD.remove();
      }
    };
  }

  static void begin(SecurityState state) {
    EXPORTER.ledger().begin(state);
  }

  static void end(SecurityState state, Context context) {
    try {
      state.request.put("ended_at", Events.now());
      for (Map<String, Object> event : EXPORTER.ledger().end(state)) {
        EXPORTER.emit(event, context, true);
      }
    } catch (Throwable error) {
      EXPORTER.ledger().count("request_completion_errors");
    }
  }

  static void diagnostic(Map<String, Object> event, Context context) {
    EXPORTER.emit(event, context, false);
  }

  private static void emit(Call call, SinkRules.Finding finding, ClassLoader loader) {
    Context context = Context.current();
    String site = logicalSite(call, loader);
    call.state.sink(finding.rule, site);
    Map<String, Object> event =
        call.state.evidence(
            finding.rule,
            finding.role,
            (call.receiver instanceof Statement
                    ? "java.sql.Statement"
                    : call.owner.replace('/', '.'))
                + "."
                + call.method,
            site,
            finding.marks,
            call.state.traceId.equals(Span.fromContext(context).getSpanContext().getTraceId())
                ? Span.fromContext(context).getSpanContext().getSpanId()
                : "");
    if (event == null) {
      return;
    }
    List<String> stack = new ArrayList<>();
    for (StackTraceElement frame : Thread.currentThread().getStackTrace()) {
      String name = frame.getClassName();
      if (name.startsWith("io.beacon.security.")
          || name.startsWith("io.opentelemetry.")
          || name.equals("java.lang.Thread")) {
        continue;
      }
      stack.add(frame.toString());
      if (stack.size() == 24) {
        break;
      }
    }
    event.put("stack", stack);
    SbomInventory current = inventory;
    if (current != null) {
      String className = call.location.substring(0, call.location.indexOf('#'));
      event.put("component", current.resolve(className, loader));
    } else {
      event.put(
          "component",
          Values.map(
              "status",
              "unresolved",
              "reason",
              Settings.enabled("beacon.security.sbom.enabled", true)
                  ? "inventory_not_started"
                  : "sbom_disabled"));
    }
    call.state.pending(event);
  }

  private static String logicalSite(Call call, ClassLoader loader) {
    if (!(call.receiver instanceof Statement)) {
      return call.location;
    }
    for (StackTraceElement frame : Thread.currentThread().getStackTrace()) {
      String name = frame.getClassName();
      if (name.startsWith("io.beacon.security.")
          || name.startsWith("io.opentelemetry.")
          || name.startsWith("java.")
          || name.startsWith("jdk.")
          || name.startsWith("sun.")
          || name.startsWith("com.sun.")
          || name.startsWith("org.springframework.")) {
        continue;
      }
      try {
        Class<?> type = Class.forName(name, false, loader);
        if (Statement.class.isAssignableFrom(type)
            || Connection.class.isAssignableFrom(type)
            || InvocationHandler.class.isAssignableFrom(type)) {
          continue;
        }
      } catch (Throwable ignored) {
        return call.location;
      }
      return name
          + "#"
          + frame.getMethodName()
          + "("
          + (frame.getFileName() == null ? "" : frame.getFileName())
          + (frame.getLineNumber() < 0 ? "" : ":" + frame.getLineNumber())
          + ")";
    }
    return call.location;
  }

  private static void after(Call call, Object result) {
    if (!call.state.active() || result == null) {
      return;
    }
    if (call.owner.equals("java/io/BufferedReader") && call.method.equals("readLine")) {
      String[] source = call.state.container(call.receiver);
      if (source != null) {
        SourceCapture.capture(call.state, "body", "body", result, source[2]);
      }
      return;
    }
    if (CallSites.isJacksonReader(call.owner) && call.method.equals("readValue")) {
      for (Object argument : call.arguments) {
        String[] source = call.state.container(argument);
        if (source != null) {
          SourceCapture.capture(call.state, "body", "body", result, source[2]);
          break;
        }
      }
      return;
    }
    if (call.arguments.length == 1
        && ((call.owner.equals("java/util/Collections") && call.method.equals("list"))
            || (call.owner.equals("org/springframework/util/StringUtils")
                && call.method.equals("toStringArray")))) {
      String[] source = call.state.container(call.arguments[0]);
      if (source != null) {
        SourceCapture.capture(call.state, source[0], source[1], result, source[2]);
      }
      return;
    }
    if (call.method.equals("nextElement")) {
      String[] source = call.state.container(call.receiver);
      if (source != null) {
        SourceCapture.capture(call.state, source[0], source[1], result, source[2]);
      }
      return;
    }
    if (call.receiver instanceof Connection
        && (call.method.equals("prepareStatement") || call.method.equals("prepareCall"))) {
      call.state.put(result, call.step(call.arg(0), 0, 0, Integer.MAX_VALUE, true));
      return;
    }
    if (SinkRules.isFileSink(call.owner, call.method)
        || SinkRules.isHttpSink(call.owner, call.method)
        || call.receiver instanceof Statement
        || call.owner.equals("java/lang/ProcessBuilder")
        || call.owner.equals("java/lang/Runtime")) {
      return;
    }
    if (networkCarrier(call.owner)) {
      network(call, result);
      return;
    }
    // Driver implementation callsites are matched by name, but unrelated execute methods
    // (for example RestTemplate.execute) do not propagate request arguments into responses.
    if (call.method.startsWith("execute")
        || call.method.equals("prepareStatement")
        || call.method.equals("prepareCall")) {
      return;
    }
    Propagation.after(call, result);
  }

  private static boolean networkCarrier(String owner) {
    return owner.equals("java/net/URL")
        || owner.equals("java/net/URI")
        || owner.startsWith("java/net/http/")
        || owner.startsWith("okhttp3/")
        || owner.startsWith("org/apache/http/")
        || owner.startsWith("org/apache/hc/");
  }

  private static void network(Call call, Object result) {
    String origin = call.state.destination(call.receiver);
    for (Object arg : call.arguments) {
      String found = call.state.destination(arg);
      if (found != null) {
        origin = found;
        break;
      }
      if (arg instanceof String && ((String) arg).contains("://")) {
        origin = (String) arg;
        break;
      }
    }
    boolean accessor = call.method.startsWith("get") || call.method.equals("uri");
    if ((call.owner.equals("java/net/URI") || call.owner.equals("java/net/URL"))
        && accessor
        && call.arguments.length == 0) {
      projectUrlPart(call, result, origin);
      return;
    }
    boolean representationPreserved = true;
    if (result instanceof URI || result instanceof URL) {
      String actual =
          result instanceof URI ? ((URI) result).toString() : ((URL) result).toExternalForm();
      representationPreserved = origin != null && origin.equals(actual);
      origin = actual;
    }
    if (result instanceof String
        && (call.method.equals("toString")
            || call.method.equals("toASCIIString")
            || call.method.equals("toExternalForm"))) {
      representationPreserved = origin != null && origin.equals(result);
      origin = (String) result;
    }
    boolean replace =
        call.method.equals("url")
            || call.method.equals("uri")
            || call.method.equals("setURI")
            || call.method.equals("setUri");
    List<Mark> marks = replace ? call.arg(0) : call.allMarks();
    call.state.put(result, call.step(marks, 0, 0, Integer.MAX_VALUE, representationPreserved));
    call.state.destination(result, origin);
  }

  private static void projectUrlPart(Call call, Object result, String origin) {
    if (!(result instanceof String) || origin == null) {
      Propagation.after(call, result);
      return;
    }
    int colon = origin.indexOf(':');
    int authority = origin.startsWith("//", colon + 1) ? colon + 3 : -1;
    int path = authority;
    if (path >= 0) {
      while (path < origin.length() && "/?#".indexOf(origin.charAt(path)) < 0) {
        path++;
      }
    } else {
      path = Math.max(0, colon + 1);
    }
    int query = origin.indexOf('?', path);
    int fragment = origin.indexOf('#', path);
    int end = fragment < 0 ? origin.length() : fragment;
    int from;
    int to;
    switch (call.method) {
      case "getScheme":
        from = 0;
        to = Math.max(0, colon);
        break;
      case "getAuthority":
        from = authority;
        to = path;
        break;
      case "getHost":
        from = authority;
        to = path;
        if (from >= 0) {
          int at = origin.lastIndexOf('@', to - 1);
          if (at >= from) {
            from = at + 1;
          }
          if (from < to && origin.charAt(from) == '[') {
            int bracket = origin.indexOf(']', from);
            if (bracket >= from && bracket < to) {
              to = bracket + 1;
            }
          } else {
            int port = origin.indexOf(':', from);
            if (port >= from && port < to) {
              to = port;
            }
          }
        }
        break;
      case "getPath":
        from = path;
        to = query >= 0 && query < end ? query : end;
        break;
      case "getQuery":
        from = query < 0 || query > end ? -1 : query + 1;
        to = end;
        break;
      case "getFile":
        from = path;
        to = end;
        break;
      default:
        Propagation.after(call, result);
        return;
    }
    if (from < 0 || to < from) {
      call.state.put(result, emptyList());
      return;
    }
    List<Mark> clipped = call.step(call.receiverMarks, -from, from, to, true);
    // Decoding may change widths; the structural slice still excludes unrelated URL parts.
    boolean unchanged = origin.substring(from, to).equals(result);
    call.state.put(
        result, unchanged ? clipped : call.step(clipped, 0, 0, Integer.MAX_VALUE, false));
  }
}

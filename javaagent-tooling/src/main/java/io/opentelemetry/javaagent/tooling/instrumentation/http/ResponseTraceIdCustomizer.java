/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.javaagent.tooling.instrumentation.http;

import com.google.auto.service.AutoService;
import io.opentelemetry.api.GlobalOpenTelemetry;
import io.opentelemetry.api.incubator.config.DeclarativeConfigProperties;
import io.opentelemetry.api.trace.Span;
import io.opentelemetry.api.trace.SpanContext;
import io.opentelemetry.context.Context;
import io.opentelemetry.instrumentation.api.incubator.config.internal.DeclarativeConfigUtil;
import io.opentelemetry.javaagent.bootstrap.http.HttpServerResponseCustomizer;
import io.opentelemetry.javaagent.bootstrap.http.HttpServerResponseMutator;
import java.util.Locale;
import java.util.logging.Logger;

@AutoService(HttpServerResponseCustomizer.class)
public final class ResponseTraceIdCustomizer implements HttpServerResponseCustomizer {
  private static final Logger logger = Logger.getLogger(ResponseTraceIdCustomizer.class.getName());

  private final boolean enabled;
  private final String headerName;

  public ResponseTraceIdCustomizer() {
    this(
        DeclarativeConfigUtil.getInstrumentationConfig(GlobalOpenTelemetry.get(), "common")
            .get("http")
            .get("server")
            .get("response_trace_id"));
  }

  ResponseTraceIdCustomizer(DeclarativeConfigProperties config) {
    this(config.getBoolean("enabled", false), config.getString("header_name", "btrace-id"));
  }

  ResponseTraceIdCustomizer(boolean enabled, String headerName) {
    this.headerName = headerName;
    this.enabled = enabled && isValidHeaderName(headerName);
    if (enabled && !this.enabled) {
      logger.warning(
          "Invalid HTTP response trace ID header name; response trace ID injection disabled");
    }
  }

  static boolean isValidHeaderName(String name) {
    if (name.isEmpty()) {
      return false;
    }
    for (int i = 0; i < name.length(); i++) {
      char c = name.charAt(i);
      if (!(c >= 'a' && c <= 'z')
          && !(c >= 'A' && c <= 'Z')
          && !(c >= '0' && c <= '9')
          && "!#$%&'*+-.^_`|~".indexOf(c) < 0) {
        return false;
      }
    }
    // These names control framing, routing, representation, or connection semantics.
    switch (name.toLowerCase(Locale.ROOT)) {
      case "content-length":
      case "transfer-encoding":
      case "connection":
      case "trailer":
      case "upgrade":
      case "keep-alive":
      case "te":
      case "host":
      case "content-type":
      case "content-encoding":
      case "content-range":
      case "location":
      case "set-cookie":
        return false;
      default:
        return true;
    }
  }

  @Override
  public <T> void customize(
      Context serverContext, T response, HttpServerResponseMutator<T> responseMutator) {
    if (!enabled) {
      return;
    }
    SpanContext spanContext = Span.fromContext(serverContext).getSpanContext();
    if (spanContext.isValid()) {
      responseMutator.appendHeaderIfAbsent(response, headerName, spanContext.getTraceId());
    }
  }

  @Override
  public <T> void customizeBeforeCommit(
      Context serverContext, T response, HttpServerResponseMutator<T> responseMutator) {
    customize(serverContext, response, responseMutator);
  }
}

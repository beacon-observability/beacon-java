/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.javaagent.tooling.instrumentation.http;

import static org.assertj.core.api.Assertions.assertThat;

import io.opentelemetry.api.incubator.config.DeclarativeConfigProperties;
import io.opentelemetry.api.trace.Span;
import io.opentelemetry.api.trace.SpanContext;
import io.opentelemetry.api.trace.TraceFlags;
import io.opentelemetry.api.trace.TraceState;
import io.opentelemetry.context.Context;
import io.opentelemetry.instrumentation.config.bridge.DeclarativeConfigBridge;
import io.opentelemetry.javaagent.bootstrap.http.HttpServerResponseMutator;
import io.opentelemetry.sdk.autoconfigure.spi.internal.DefaultConfigProperties;
import java.util.HashMap;
import java.util.Map;
import java.util.TreeMap;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class ResponseTraceIdCustomizerTest {
  private static final String TRACE_ID = "000000000000000000000000000000ab";
  private static final Context SERVER_CONTEXT =
      Context.root()
          .with(
              Span.wrap(
                  SpanContext.create(
                      TRACE_ID,
                      "0000000000000001",
                      TraceFlags.getDefault(),
                      TraceState.getDefault())));

  private static final HttpServerResponseMutator<Map<String, String>> MUTATOR =
      new HttpServerResponseMutator<Map<String, String>>() {
        @Override
        public void appendHeader(Map<String, String> response, String name, String value) {
          response.put(name, value);
        }

        @Override
        public void appendHeaderIfAbsent(Map<String, String> response, String name, String value) {
          response.putIfAbsent(name, value);
        }
      };

  @ParameterizedTest
  @ValueSource(booleans = {true, false})
  void flatConfigurationAndDefaults(boolean configured) {
    Map<String, String> properties = new HashMap<>();
    if (configured) {
      properties.put("otel.instrumentation.common.http.server.response-trace-id.enabled", "true");
      properties.put(
          "otel.instrumentation.common.http.server.response-trace-id.header-name", "x-trace");
    }
    DeclarativeConfigProperties config =
        DeclarativeConfigBridge.createInstrumentationConfig(
                DefaultConfigProperties.createFromMap(properties))
            .getInstrumentationConfig()
            .get("java")
            .get("common")
            .get("http")
            .get("server")
            .get("response_trace_id");
    Map<String, String> response = new TreeMap<>();
    new ResponseTraceIdCustomizer(config).customize(SERVER_CONTEXT, response, MUTATOR);
    if (configured) {
      assertThat(response).containsEntry("x-trace", TRACE_ID);
    } else {
      assertThat(response).isEmpty();
    }
  }

  @Test
  void validNonRecordingSpan() {
    Map<String, String> response = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
    new ResponseTraceIdCustomizer(true, "btrace-id").customize(SERVER_CONTEXT, response, MUTATOR);
    assertThat(response).containsEntry("btrace-id", TRACE_ID);
  }

  @Test
  void disabledAndInvalidContexts() {
    Map<String, String> response = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
    new ResponseTraceIdCustomizer(false, "btrace-id").customize(SERVER_CONTEXT, response, MUTATOR);
    new ResponseTraceIdCustomizer(true, "btrace-id").customize(Context.root(), response, MUTATOR);
    assertThat(response).isEmpty();
  }

  @Test
  void preservesApplicationHeaderAndCustomName() {
    Map<String, String> response = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
    response.put("X-Correlation", "application");
    ResponseTraceIdCustomizer customizer = new ResponseTraceIdCustomizer(true, "x-correlation");
    customizer.customizeBeforeCommit(SERVER_CONTEXT, response, MUTATOR);
    assertThat(response).containsOnlyKeys("X-Correlation").containsValue("application");
    response.clear();
    customizer.customizeBeforeCommit(SERVER_CONTEXT, response, MUTATOR);
    assertThat(response).containsEntry("x-correlation", TRACE_ID);
  }

  @Test
  void legacyMutatorDoesNotWrite() {
    Map<String, String> response = new TreeMap<>();
    new ResponseTraceIdCustomizer(true, "btrace-id").customize(SERVER_CONTEXT, response, Map::put);
    assertThat(response).isEmpty();
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "",
        "bad name",
        "x:y",
        "x\r\ny",
        "跟踪",
        "Content-Length",
        "TRANSFER-ENCODING",
        "Connection",
        "Set-Cookie",
        ":status"
      })
  void invalidHeaderName(String name) {
    assertThat(ResponseTraceIdCustomizer.isValidHeaderName(name)).isFalse();
    Map<String, String> response = new TreeMap<>();
    new ResponseTraceIdCustomizer(true, name).customize(SERVER_CONTEXT, response, MUTATOR);
    assertThat(response).isEmpty();
  }

  @ParameterizedTest
  @ValueSource(strings = {"btrace-id", "X-Trace-ID", "!#$%&'*+-.^_`|~"})
  void validHeaderName(String name) {
    assertThat(ResponseTraceIdCustomizer.isValidHeaderName(name)).isTrue();
  }
}

/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.javaagent.instrumentation.springai.v1_0;

import io.opentelemetry.api.trace.Span;
import io.opentelemetry.context.Context;
import javax.annotation.Nullable;
import org.springframework.ai.chat.model.ChatResponse;

/** Best-effort content collection must never become part of application control flow. */
final class SpringAiTelemetry {
  static void onStart(Context context, SpringAiRequest request) {
    try {
      SpringAiMessageAttributes.setSystemInstructions(context, request);
      SpringAiMessageAttributes.setInputMessages(context, request);
      SpringAiMessageEvents.emitPromptEvents(context, request);
    } catch (Throwable ignored) {
      // A content getter or log processor can fail independently of the model call.
    }
  }

  static void onEnd(
      Context context,
      SpringAiRequest request,
      @Nullable ChatResponse response,
      @Nullable Throwable error) {
    try {
      SpringAiMessageAttributes.setOutputMessages(context, response, null);
      SpringAiMessageEvents.emitResponseEvents(context, request, response, null);
    } catch (Throwable ignored) {
      // Always complete the span even if optional content extraction fails.
    }
    try {
      SpringAiSingletons.instrumenter().end(context, request, response, error);
    } catch (Throwable ignored) {
      Span.fromContext(context).end();
    }
  }

  private SpringAiTelemetry() {}
}

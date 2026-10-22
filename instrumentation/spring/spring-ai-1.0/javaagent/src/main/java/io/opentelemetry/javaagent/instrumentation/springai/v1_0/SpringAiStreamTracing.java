/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.javaagent.instrumentation.springai.v1_0;

import io.opentelemetry.context.Context;
import io.opentelemetry.instrumentation.api.instrumenter.Instrumenter;
import io.opentelemetry.instrumentation.reactor.v3_1.ContextPropagationOperator;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import org.springframework.ai.chat.model.ChatResponse;
import reactor.core.publisher.Flux;

public final class SpringAiStreamTracing {
  public static Flux<ChatResponse> wrap(Flux<ChatResponse> source, SpringAiRequest request) {
    return Flux.defer(
        () -> {
          Context context;
          try {
            Instrumenter<SpringAiRequest, ChatResponse> instrumenter =
                SpringAiSingletons.instrumenter();
            Context parent = Context.current();
            if (Boolean.TRUE.equals(parent.get(SpringAiSingletons.CHAT_ACTIVE))
                || !instrumenter.shouldStart(parent, request)) {
              return source;
            }
            context =
                instrumenter.start(parent, request).with(SpringAiSingletons.CHAT_ACTIVE, true);
          } catch (Throwable ignored) {
            return source;
          }
          try {
            SpringAiTelemetry.onStart(context, request);
            boolean events = SpringAiSingletons.captureMessageContent();
            boolean attributes = SpringAiSingletons.captureMessageContentAsSpanAttributes();
            int budget = SpringAiSingletons.streamContentMaxLength();
            int perChoiceLimit =
                events ? budget : SpringAiSingletons.messageContentSpanAttributeMaxLength();
            SpringAiResponseAccumulator responses =
                new SpringAiResponseAccumulator(events || attributes, perChoiceLimit, budget);
            AtomicBoolean ended = new AtomicBoolean();
            AtomicReference<Throwable> error = new AtomicReference<>();
            Flux<ChatResponse> traced =
                source
                    .doOnNext(
                        response -> {
                          try {
                            responses.add(response);
                          } catch (Throwable ignored) {
                            // Telemetry getters must not turn a successful chunk into onError.
                          }
                        })
                    .doOnError(error::set)
                    .doFinally(
                        signal -> {
                          if (ended.compareAndSet(false, true)) {
                            ChatResponse response = null;
                            try {
                              response = responses.response();
                            } catch (Throwable ignored) {
                              // Complete without response attributes if aggregation fails.
                            }
                            SpringAiTelemetry.onEnd(context, request, response, error.get());
                          }
                        });
            return ContextPropagationOperator.runWithContext(traced, context);
          } catch (Throwable ignored) {
            SpringAiTelemetry.onEnd(context, request, null, null);
            return source;
          }
        });
  }

  private SpringAiStreamTracing() {}
}

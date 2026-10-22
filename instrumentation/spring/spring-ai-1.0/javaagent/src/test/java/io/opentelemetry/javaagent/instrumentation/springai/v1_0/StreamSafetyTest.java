/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.javaagent.instrumentation.springai.v1_0;

import static java.util.Collections.singletonList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.opentelemetry.instrumentation.testing.junit.AgentInstrumentationExtension;
import io.opentelemetry.instrumentation.testing.junit.InstrumentationExtension;
import io.opentelemetry.javaagent.instrumentation.springai.v1_0.app.TestChatModel;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.springframework.ai.chat.messages.AssistantMessage;
import org.springframework.ai.chat.model.ChatResponse;
import org.springframework.ai.chat.model.Generation;
import org.springframework.ai.chat.prompt.Prompt;
import reactor.core.publisher.Flux;

@SuppressWarnings("PublicApiNamedStreamShouldReturnStream")
class StreamSafetyTest {
  @RegisterExtension
  static final InstrumentationExtension testing = AgentInstrumentationExtension.create();

  @Test
  void failingResponseGetterDoesNotReplaceOrDropTheBusinessChunk() {
    ChatResponse chunk =
        new ChatResponse(singletonList(new Generation(new AssistantMessage("ok")))) {
          @Override
          public List<Generation> getResults() {
            throw new IllegalStateException("telemetry getter failure");
          }
        };
    TestChatModel model = model(Flux.just(chunk));
    testing.runWithSpan(
        "parent", () -> assertThat(model.stream(new Prompt("hello")).blockLast()).isSameAs(chunk));
    assertOneChat();
  }

  @Test
  void failingPromptContentGetterDoesNotPreventSubscription() {
    AssistantMessage message =
        new AssistantMessage("tool request") {
          @Override
          public String getText() {
            throw new IllegalStateException("content unavailable");
          }
        };
    Prompt prompt = new Prompt(singletonList(message));
    testing.runWithSpan(
        "parent", () -> assertThat(new TestChatModel().stream(prompt).blockLast()).isNotNull());
    assertOneChat();
  }

  @Test
  void preservesTheSourceFailureAndEndsTheSpan() {
    IllegalArgumentException failure = new IllegalArgumentException("business failure");
    TestChatModel model = model(Flux.error(failure));
    testing.runWithSpan(
        "parent",
        () ->
            assertThatThrownBy(() -> model.stream(new Prompt("hello")).blockLast())
                .isSameAs(failure));
    assertOneChat();
  }

  @Test
  void cancellationEndsTheSpanOnce() {
    ChatResponse chunk =
        new ChatResponse(singletonList(new Generation(new AssistantMessage("ok"))));
    TestChatModel model = model(Flux.concat(Flux.just(chunk), Flux.never()));
    testing.runWithSpan(
        "parent",
        () -> assertThat(model.stream(new Prompt("hello")).take(1).blockLast()).isSameAs(chunk));
    assertOneChat();
  }

  private static TestChatModel model(Flux<ChatResponse> chunks) {
    return new TestChatModel() {
      @Override
      public Flux<ChatResponse> stream(Prompt prompt) {
        return chunks;
      }
    };
  }

  private static void assertOneChat() {
    testing.waitAndAssertTraces(
        trace ->
            trace.hasSpansSatisfyingExactly(
                span -> span.hasName("parent").hasNoParent(),
                span -> span.hasName("chat").hasParent(trace.getSpan(0))));
  }
}

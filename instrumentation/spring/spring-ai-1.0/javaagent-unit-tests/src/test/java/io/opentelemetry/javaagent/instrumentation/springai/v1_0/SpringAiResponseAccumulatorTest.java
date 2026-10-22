/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.javaagent.instrumentation.springai.v1_0;

import static java.util.Arrays.asList;
import static java.util.Collections.emptyList;
import static java.util.Collections.singletonList;
import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.ai.chat.messages.AssistantMessage;
import org.springframework.ai.chat.metadata.ChatGenerationMetadata;
import org.springframework.ai.chat.metadata.ChatResponseMetadata;
import org.springframework.ai.chat.metadata.DefaultUsage;
import org.springframework.ai.chat.model.ChatResponse;
import org.springframework.ai.chat.model.Generation;

class SpringAiResponseAccumulatorTest {
  @Test
  void preservesSeparateChoicesAndFinishReasonsAcrossUsageOnlyChunk() {
    SpringAiResponseAccumulator accumulator = new SpringAiResponseAccumulator(true, 100, 200);
    accumulator.add(
        new ChatResponse(asList(generation("Hello", 0, null), generation("Other", 1, null))));
    accumulator.add(
        new ChatResponse(asList(generation(null, 0, "stop"), generation(" choice", 1, "length"))));
    accumulator.add(
        new ChatResponse(
            emptyList(),
            ChatResponseMetadata.builder()
                .id("response")
                .model("model")
                .usage(new DefaultUsage(7, 9))
                .build()));

    ChatResponse result = accumulator.response();
    assertThat(result.getResults())
        .extracting(g -> g.getOutput().getText())
        .containsExactly("Hello", "Other choice");
    assertThat(result.getResults())
        .extracting(g -> g.getMetadata().getFinishReason())
        .containsExactly("stop", "length");
    assertThat(result.getMetadata().getUsage().getCompletionTokens()).isEqualTo(9);
    assertThat(result.getMetadata().getId()).isEqualTo("response");
  }

  @Test
  void disabledContentDoesNotReadOrRetainChunkText() {
    SpringAiResponseAccumulator accumulator = new SpringAiResponseAccumulator(false, 100, 100);
    AssistantMessage message =
        new AssistantMessage("sensitive") {
          @Override
          public String getText() {
            throw new IllegalStateException("must not access disabled content");
          }
        };
    accumulator.add(new ChatResponse(singletonList(new Generation(message))));
    assertThat(accumulator.response().getResult().getOutput().getText()).isNull();
  }

  @Test
  void enforcesBothPerChoiceAndTotalLimitsWithoutSplittingSurrogates() {
    SpringAiResponseAccumulator accumulator = new SpringAiResponseAccumulator(true, 4, 6);
    accumulator.add(
        new ChatResponse(asList(generation("abc😀", 0, null), generation("xyzxyz", 1, null))));
    ChatResponse result = accumulator.response();
    assertThat(result.getResults())
        .extracting(g -> g.getOutput().getText())
        .containsExactly("abc", "xyz");
    assertThat(result.getResults())
        .allSatisfy(g -> assertThat(SpringAiResponseAccumulator.truncated(g)).isTrue());
    accumulator.add(new ChatResponse(singletonList(generation("more", 0, "stop"))));
    assertThat(accumulator.response().getResult().getOutput().getText()).isEqualTo("abc");
  }

  private static Generation generation(String text, int index, String finish) {
    ChatGenerationMetadata.Builder metadata =
        ChatGenerationMetadata.builder().metadata("index", index);
    if (finish != null) {
      metadata.finishReason(finish);
    }
    return new Generation(new AssistantMessage(text), metadata.build());
  }
}

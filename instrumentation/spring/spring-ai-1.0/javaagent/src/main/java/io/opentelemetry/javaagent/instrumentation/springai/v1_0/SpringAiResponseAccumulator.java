/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.javaagent.instrumentation.springai.v1_0;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import javax.annotation.Nullable;
import org.springframework.ai.chat.messages.AssistantMessage;
import org.springframework.ai.chat.metadata.ChatGenerationMetadata;
import org.springframework.ai.chat.metadata.ChatResponseMetadata;
import org.springframework.ai.chat.metadata.Usage;
import org.springframework.ai.chat.model.ChatResponse;
import org.springframework.ai.chat.model.Generation;

/** Retains bounded telemetry, never the original chunks or their tool payloads. */
final class SpringAiResponseAccumulator {
  static final String TRUNCATED = "otel.content_truncated";
  private static final int MAX_CHOICES = 128;
  private final Map<Integer, Choice> choices = new TreeMap<>();
  private final boolean captureContent;
  private final int perChoiceLimit;
  private int remaining;
  private String id = "";
  private String model = "";
  @Nullable private Usage usage;

  SpringAiResponseAccumulator(boolean captureContent, int perChoiceLimit, int totalLimit) {
    this.captureContent = captureContent;
    this.perChoiceLimit = perChoiceLimit;
    this.remaining = totalLimit;
  }

  synchronized void add(ChatResponse response) {
    ChatResponseMetadata metadata = response.getMetadata();
    if (metadata != null) {
      if (metadata.getId() != null && !metadata.getId().isEmpty()) {
        id = metadata.getId();
      }
      if (metadata.getModel() != null && !metadata.getModel().isEmpty()) {
        model = metadata.getModel();
      }
      Usage nextUsage = metadata.getUsage();
      if (nextUsage != null
          && (usage == null
              || positive(nextUsage.getPromptTokens())
              || positive(nextUsage.getCompletionTokens()))) {
        usage = nextUsage;
      }
    }
    List<Generation> results = response.getResults();
    for (int i = 0; i < Math.min(results.size(), MAX_CHOICES); i++) {
      Generation generation = results.get(i);
      int index = choiceIndex(generation, i);
      Choice choice = choices.get(index);
      if (choice == null) {
        if (choices.size() == MAX_CHOICES) {
          continue;
        }
        choice = new Choice(captureContent);
        choices.put(index, choice);
      }
      ChatGenerationMetadata generationMetadata = generation.getMetadata();
      String finish = generationMetadata == null ? null : generationMetadata.getFinishReason();
      if (finish != null && !finish.isEmpty()) {
        choice.finishReason = finish;
      }
      if (!captureContent || choice.truncated) {
        continue;
      }
      String text = generation.getOutput().getText();
      if (text == null || text.isEmpty()) {
        continue;
      }
      StringBuilder content = choice.content;
      if (content == null) {
        continue;
      }
      int length = Math.min(text.length(), Math.min(remaining, perChoiceLimit - content.length()));
      if (length > 0
          && length < text.length()
          && Character.isHighSurrogate(text.charAt(length - 1))) {
        length--;
      }
      content.append(text, 0, length);
      remaining -= length;
      choice.truncated |= length < text.length();
    }
  }

  synchronized ChatResponse response() {
    List<Generation> generations = new ArrayList<>();
    for (Map.Entry<Integer, Choice> entry : choices.entrySet()) {
      Choice choice = entry.getValue();
      String text = choice.content == null ? null : choice.content.toString();
      if (text != null
          && !text.isEmpty()
          && Character.isHighSurrogate(text.charAt(text.length() - 1))) {
        text = text.substring(0, text.length() - 1);
        choice.truncated = true;
      }
      ChatGenerationMetadata.Builder metadata =
          ChatGenerationMetadata.builder().metadata("index", entry.getKey());
      if (choice.finishReason != null) {
        metadata.finishReason(choice.finishReason);
      }
      if (choice.truncated) {
        metadata.metadata(TRUNCATED, true);
      }
      generations.add(new Generation(new AssistantMessage(text), metadata.build()));
    }
    ChatResponseMetadata.Builder metadata = ChatResponseMetadata.builder().id(id).model(model);
    if (usage != null) {
      metadata.usage(usage);
    }
    return new ChatResponse(generations, metadata.build());
  }

  static int choiceIndex(Generation generation, int fallback) {
    Object index = generation.getMetadata() == null ? null : generation.getMetadata().get("index");
    return index instanceof Integer value && value >= 0 ? value : fallback;
  }

  static boolean truncated(Generation generation) {
    return generation.getMetadata() != null
        && Boolean.TRUE.equals(generation.getMetadata().get(TRUNCATED));
  }

  private static boolean positive(@Nullable Integer value) {
    return value != null && value > 0;
  }

  private static final class Choice {
    @Nullable final StringBuilder content;
    @Nullable String finishReason;
    boolean truncated;

    Choice(boolean capture) {
      content = capture ? new StringBuilder() : null;
    }
  }
}

/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.javaagent.instrumentation.springai.v1_0;

import java.util.Locale;
import org.springframework.ai.chat.prompt.Prompt;

public final class SpringAiRequest {
  private final Prompt prompt;
  private final String provider;
  private final boolean streaming;

  public static SpringAiRequest create(Prompt prompt, Object chatModel, boolean streaming) {
    return new SpringAiRequest(prompt, providerName(chatModel), streaming);
  }

  private SpringAiRequest(Prompt prompt, String provider, boolean streaming) {
    this.prompt = prompt;
    this.provider = provider;
    this.streaming = streaming;
  }

  public Prompt prompt() {
    return prompt;
  }

  public String provider() {
    return provider;
  }

  public boolean isStreaming() {
    return streaming;
  }

  private static String providerName(Object chatModel) {
    String className = chatModel.getClass().getSimpleName();
    int proxyMarker = className.indexOf('$');
    if (proxyMarker >= 0) {
      className = className.substring(0, proxyMarker);
    }
    if (className.endsWith("ChatModel")) {
      className = className.substring(0, className.length() - "ChatModel".length());
    }
    return className.isEmpty() ? "spring-ai" : className.toLowerCase(Locale.ROOT);
  }
}

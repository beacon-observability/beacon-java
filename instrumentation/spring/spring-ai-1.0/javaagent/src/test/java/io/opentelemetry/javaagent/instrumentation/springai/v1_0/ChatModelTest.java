/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.javaagent.instrumentation.springai.v1_0;

import static io.opentelemetry.api.common.AttributeKey.booleanKey;
import static io.opentelemetry.api.common.AttributeKey.stringKey;
import static io.opentelemetry.api.trace.SpanKind.CLIENT;
import static io.opentelemetry.api.trace.SpanKind.INTERNAL;
import static io.opentelemetry.sdk.testing.assertj.OpenTelemetryAssertions.equalTo;
import static io.opentelemetry.semconv.incubating.GenAiIncubatingAttributes.GEN_AI_OPERATION_NAME;
import static io.opentelemetry.semconv.incubating.GenAiIncubatingAttributes.GEN_AI_PROVIDER_NAME;
import static io.opentelemetry.semconv.incubating.GenAiIncubatingAttributes.GEN_AI_REQUEST_MODEL;
import static io.opentelemetry.semconv.incubating.GenAiIncubatingAttributes.GEN_AI_REQUEST_STREAM;
import static io.opentelemetry.semconv.incubating.GenAiIncubatingAttributes.GEN_AI_RESPONSE_FINISH_REASONS;
import static io.opentelemetry.semconv.incubating.GenAiIncubatingAttributes.GEN_AI_RESPONSE_ID;
import static io.opentelemetry.semconv.incubating.GenAiIncubatingAttributes.GEN_AI_RESPONSE_MODEL;
import static io.opentelemetry.semconv.incubating.GenAiIncubatingAttributes.GEN_AI_USAGE_INPUT_TOKENS;
import static io.opentelemetry.semconv.incubating.GenAiIncubatingAttributes.GEN_AI_USAGE_OUTPUT_TOKENS;
import static io.opentelemetry.semconv.incubating.GenAiIncubatingAttributes.GenAiOperationNameIncubatingValues.CHAT;
import static java.util.Arrays.asList;
import static java.util.Collections.singletonList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.opentelemetry.api.common.KeyValue;
import io.opentelemetry.api.common.Value;
import io.opentelemetry.api.trace.Span;
import io.opentelemetry.api.trace.SpanContext;
import io.opentelemetry.instrumentation.testing.junit.AgentInstrumentationExtension;
import io.opentelemetry.instrumentation.testing.junit.InstrumentationExtension;
import io.opentelemetry.javaagent.instrumentation.springai.v1_0.app.TestChatModel;
import javax.annotation.Nullable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.springframework.ai.chat.messages.AssistantMessage;
import org.springframework.ai.chat.messages.SystemMessage;
import org.springframework.ai.chat.messages.UserMessage;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.ai.chat.model.ChatResponse;
import org.springframework.ai.chat.prompt.DefaultChatOptions;
import org.springframework.ai.chat.prompt.Prompt;

@SuppressWarnings({"deprecation", "PublicApiNamedStreamShouldReturnStream"})
class ChatModelTest {

  private static final String MODEL = "test-model";
  private static final boolean CAPTURE_MESSAGE_CONTENT_AS_SPAN_ATTRIBUTES =
      Boolean.getBoolean(
          "otel.instrumentation.spring-ai.experimental.capture-message-content-as-span-attributes.enabled");

  @RegisterExtension
  static final InstrumentationExtension testing = AgentInstrumentationExtension.create();

  private final ChatModel chatModel = new TestChatModel();

  @Test
  void nestedModelCallsUseOneChatScopeAndParentTheChildWork() {
    ChatModel model =
        new TestChatModel() {
          @Override
          public ChatResponse call(Prompt prompt) {
            return testing.runWithSpan("child", () -> super.call(prompt));
          }
        };
    testing.runWithSpan("parent", () -> model.call(prompt()));
    testing.waitAndAssertTraces(
        trace ->
            trace.hasSpansSatisfyingExactly(
                span -> span.hasName("parent").hasNoParent(),
                span -> span.hasName("chat " + MODEL).hasParent(trace.getSpan(0)),
                span -> span.hasName("child").hasParent(trace.getSpan(1))));
  }

  @Test
  void failureRestoresScopeAndPreservesTheOriginalException() {
    IllegalStateException failure = new IllegalStateException("model failure");
    ChatModel model =
        new TestChatModel() {
          @Override
          public ChatResponse call(Prompt prompt) {
            throw failure;
          }
        };
    testing.runWithSpan(
        "parent",
        () -> {
          SpanContext parent = Span.current().getSpanContext();
          assertThatThrownBy(() -> model.call(prompt())).isSameAs(failure);
          assertThat(Span.current().getSpanContext()).isEqualTo(parent);
        });
    testing.waitAndAssertTraces(
        trace ->
            trace.hasSpansSatisfyingExactly(
                span -> span.hasName("parent").hasNoParent(),
                span -> span.hasName("chat " + MODEL).hasParent(trace.getSpan(0))));
  }

  @Test
  void nullAssistantTextDoesNotAbortTheCallOrLeakItsSpan() {
    testing.runWithSpan(
        "parent",
        () ->
            chatModel.call(
                new Prompt(asList(new UserMessage("tool follow-up"), new AssistantMessage(null)))));
    testing.waitAndAssertTraces(
        trace ->
            trace.hasSpansSatisfyingExactly(
                span -> span.hasName("parent").hasNoParent(),
                span -> span.hasKind(CLIENT).hasParent(trace.getSpan(0))));
  }

  @Test
  void call() {
    testing.runWithSpan("parent", () -> chatModel.call(prompt()));

    SpanContext spanContext = testing.waitForTraces(1).get(0).get(1).getSpanContext();
    assertTraces(false);
    assertMessageEvents(spanContext);
  }

  @Test
  void stream() {
    testing.runWithSpan("parent", () -> chatModel.stream(prompt()).blockLast());

    SpanContext spanContext = testing.waitForTraces(1).get(0).get(1).getSpanContext();
    assertTraces(true);
    assertMessageEvents(spanContext);
  }

  @Test
  void messageSpanAttributeIsTruncatedWithoutChangingItsJsonStructure() {
    // The limit falls between the surrogate pair; the emoji must not be split.
    String content = repeatedContent(8191) + "😀";
    testing.runWithSpan("parent", () -> chatModel.call(new Prompt(content)));

    assertThat(
            testing
                .waitForTraces(1)
                .get(0)
                .get(1)
                .getAttributes()
                .get(stringKey("gen_ai.input.messages")))
        .isEqualTo(
            messageSpanAttribute(
                "[{\"role\":\"user\",\"parts\":[{\"type\":\"text\",\"content\":\""
                    + repeatedContent(8191)
                    + "\"}]}]"));
    assertThat(
            testing
                .waitForTraces(1)
                .get(0)
                .get(1)
                .getAttributes()
                .get(booleanKey("gen_ai.input.messages.truncated")))
        .isEqualTo(messageSpanAttribute(true));
  }

  @Test
  void escapesSystemAndInputMessages() {
    testing.runWithSpan(
        "parent",
        () ->
            chatModel.call(
                new Prompt(
                    asList(
                        new SystemMessage("line\nvalue"), new UserMessage("quoted \"value\"")))));

    assertThat(
            testing
                .waitForTraces(1)
                .get(0)
                .get(1)
                .getAttributes()
                .get(stringKey("gen_ai.system_instructions")))
        .isEqualTo(messageSpanAttribute("[{\"type\":\"text\",\"content\":\"line\\nvalue\"}]"));
    assertThat(
            testing
                .waitForTraces(1)
                .get(0)
                .get(1)
                .getAttributes()
                .get(stringKey("gen_ai.input.messages")))
        .isEqualTo(
            messageSpanAttribute(
                "[{\"role\":\"user\",\"parts\":[{\"type\":\"text\",\"content\":\"quoted \\\"value\\\"\"}]}]"));
  }

  @Test
  void escapesOutputMessage() {
    testing.runWithSpan("parent", () -> new TestChatModel("first\n\"quoted\"").call(prompt()));

    assertThat(
            testing
                .waitForTraces(1)
                .get(0)
                .get(1)
                .getAttributes()
                .get(stringKey("gen_ai.output.messages")))
        .isEqualTo(
            messageSpanAttribute(
                "[{\"role\":\"assistant\",\"parts\":[{\"type\":\"text\",\"content\":\"first\\n\\\"quoted\\\"\"}],\"finish_reason\":\"stop\"}]"));
  }

  private static void assertTraces(boolean streaming) {
    testing.waitAndAssertTraces(
        trace ->
            trace.hasSpansSatisfyingExactly(
                span -> span.hasName("parent").hasKind(INTERNAL).hasNoParent(),
                span ->
                    span.hasName("chat " + MODEL)
                        .hasKind(CLIENT)
                        .hasParent(trace.getSpan(0))
                        .hasAttributesSatisfyingExactly(
                            equalTo(GEN_AI_PROVIDER_NAME, "test"),
                            equalTo(GEN_AI_OPERATION_NAME, CHAT),
                            equalTo(GEN_AI_REQUEST_MODEL, MODEL),
                            equalTo(GEN_AI_REQUEST_STREAM, streaming ? true : null),
                            equalTo(GEN_AI_RESPONSE_FINISH_REASONS, singletonList("stop")),
                            equalTo(GEN_AI_RESPONSE_ID, "response-id"),
                            equalTo(GEN_AI_RESPONSE_MODEL, MODEL),
                            equalTo(GEN_AI_USAGE_INPUT_TOKENS, 3L),
                            equalTo(GEN_AI_USAGE_OUTPUT_TOKENS, 2L),
                            equalTo(
                                stringKey("gen_ai.system_instructions"),
                                messageSpanAttribute(
                                    "[{\"type\":\"text\",\"content\":\"You are a helpful tracing assistant.\"}]")),
                            equalTo(
                                stringKey("gen_ai.input.messages"),
                                messageSpanAttribute(
                                    "[{\"role\":\"user\",\"parts\":[{\"type\":\"text\",\"content\":\"Tell me about traces\"}]}]")),
                            equalTo(
                                stringKey("gen_ai.output.messages"),
                                messageSpanAttribute(
                                    "[{\"role\":\"assistant\",\"parts\":[{\"type\":\"text\",\"content\":\"A trace represents an end-to-end request.\"}],\"finish_reason\":\"stop\"}]")))));
  }

  private static void assertMessageEvents(SpanContext spanContext) {
    testing.waitAndAssertLogRecords(
        log ->
            log.hasAttributesSatisfyingExactly(
                    equalTo(GEN_AI_PROVIDER_NAME, "test"),
                    equalTo(stringKey("event.name"), "gen_ai.system.message"))
                .hasSpanContext(spanContext)
                .hasBody(
                    Value.of(
                        KeyValue.of("content", Value.of("You are a helpful tracing assistant.")))),
        log ->
            log.hasAttributesSatisfyingExactly(
                    equalTo(GEN_AI_PROVIDER_NAME, "test"),
                    equalTo(stringKey("event.name"), "gen_ai.user.message"))
                .hasSpanContext(spanContext)
                .hasBody(Value.of(KeyValue.of("content", Value.of("Tell me about traces")))),
        log ->
            log.hasAttributesSatisfyingExactly(
                    equalTo(GEN_AI_PROVIDER_NAME, "test"),
                    equalTo(stringKey("event.name"), "gen_ai.choice"))
                .hasSpanContext(spanContext)
                .hasBody(
                    Value.of(
                        KeyValue.of("finish_reason", Value.of("stop")),
                        KeyValue.of("index", Value.of(0)),
                        KeyValue.of(
                            "message",
                            Value.of(
                                KeyValue.of(
                                    "content",
                                    Value.of("A trace represents an end-to-end request.")))))));
  }

  private static Prompt prompt() {
    DefaultChatOptions options = new DefaultChatOptions();
    options.setModel(MODEL);
    return new Prompt(
        asList(
            new SystemMessage("You are a helpful tracing assistant."),
            new UserMessage("Tell me about traces")),
        options);
  }

  private static String repeatedContent(int length) {
    StringBuilder content = new StringBuilder(length);
    for (int index = 0; index < length; index++) {
      content.append('a');
    }
    return content.toString();
  }

  @Nullable
  private static <T> T messageSpanAttribute(T value) {
    return CAPTURE_MESSAGE_CONTENT_AS_SPAN_ATTRIBUTES ? value : null;
  }
}

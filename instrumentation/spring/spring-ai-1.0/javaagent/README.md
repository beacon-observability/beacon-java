# Settings for the Spring AI instrumentation

| System property                                      | Type    | Default | Description                              |
| ---------------------------------------------------- | ------- | ------- | ---------------------------------------- |
| `otel.instrumentation.genai.capture-message-content` | Boolean | `false` | Record content of user and LLM messages in log events. |
| `otel.instrumentation.spring-ai.experimental.capture-message-content-as-span-attributes.enabled` | Boolean | `false` | Record content in the experimental `gen_ai.input.messages` and `gen_ai.output.messages` span attributes. |
| `otel.instrumentation.spring-ai.experimental.message-content-span-attribute.max-length` | Integer | `8192` | Maximum number of characters captured for each message content in a span attribute. |
| `otel.instrumentation.spring-ai.experimental.stream-content.max-length` | Integer | `65536` | Maximum total characters retained for one stream, across all choices and content destinations. `0` retains no text. |

This instrumentation creates GenAI client spans for `ChatModel.call` and `ChatModel.stream`.
It is provider-neutral and supports Spring AI 1.x model implementations.

Streaming telemetry retains text only when at least one content destination is enabled. With only
span attributes enabled, the per-message limit also applies while buffering. Streams retain at most
128 choices. Content cut by a buffer limit is marked with `gen_ai.output.messages.truncated` on
content span attributes and `content_truncated` in choice-event messages. Text from distinct choices
is accumulated separately; usage-only final chunks do not discard earlier finish reasons.

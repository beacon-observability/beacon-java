# Spring AI Alibaba Agent content settings

Agent and tool spans propagate their context to work performed inside the operation. Tool names and
call identifiers are recorded without tool payloads by default.

| System property | Type | Default | Description |
| --- | --- | --- | --- |
| `otel.instrumentation.genai.capture-message-content` | Boolean | `false` | Opt in to collecting tool arguments and successful results. Payloads may contain sensitive data. |
| `otel.instrumentation.spring-ai-alibaba-agent.experimental.tool-content.max-length` | Integer | `8192` | Maximum characters per captured argument or result. `0` retains no payload text. |

Captured payloads cut at the limit carry `gen_ai.tool.call.arguments.truncated=true` or
`gen_ai.tool.call.result.truncated=true`. Truncation does not split UTF-16 surrogate pairs.
Failed tool calls do not record a result payload.

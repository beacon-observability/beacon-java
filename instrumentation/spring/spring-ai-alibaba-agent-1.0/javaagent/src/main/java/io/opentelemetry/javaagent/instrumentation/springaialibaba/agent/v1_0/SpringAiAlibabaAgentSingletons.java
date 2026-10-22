/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.javaagent.instrumentation.springaialibaba.agent.v1_0;

import static io.opentelemetry.api.common.AttributeKey.booleanKey;
import static io.opentelemetry.api.common.AttributeKey.stringKey;

import com.alibaba.cloud.ai.graph.agent.interceptor.ToolCallResponse;
import io.opentelemetry.api.GlobalOpenTelemetry;
import io.opentelemetry.api.common.AttributesBuilder;
import io.opentelemetry.api.trace.StatusCode;
import io.opentelemetry.context.Context;
import io.opentelemetry.instrumentation.api.incubator.config.internal.DeclarativeConfigUtil;
import io.opentelemetry.instrumentation.api.instrumenter.AttributesExtractor;
import io.opentelemetry.instrumentation.api.instrumenter.Instrumenter;
import io.opentelemetry.instrumentation.api.instrumenter.InstrumenterBuilder;
import io.opentelemetry.instrumentation.api.instrumenter.SpanKindExtractor;
import io.opentelemetry.instrumentation.api.instrumenter.SpanStatusExtractor;
import javax.annotation.Nullable;

public final class SpringAiAlibabaAgentSingletons {
  private static final String INSTRUMENTATION_NAME = "io.opentelemetry.spring-ai-alibaba-agent-1.0";
  private static final boolean CAPTURE_TOOL_CONTENT =
      DeclarativeConfigUtil.getInstrumentationConfig(GlobalOpenTelemetry.get(), "common")
          .get("gen_ai")
          .getBoolean("capture_message_content", false);
  private static final int TOOL_CONTENT_MAX_LENGTH =
      (int)
          Math.min(
              Integer.MAX_VALUE,
              Math.max(
                  0,
                  DeclarativeConfigUtil.getInstrumentationConfig(
                          GlobalOpenTelemetry.get(), "spring_ai_alibaba_agent")
                      .get("tool_content/development")
                      .getLong("max_length", 8192)));

  public static boolean captureToolContent() {
    return CAPTURE_TOOL_CONTENT;
  }

  public static int toolContentMaxLength() {
    return TOOL_CONTENT_MAX_LENGTH;
  }

  static String boundContent(String content) {
    int end = Math.min(content.length(), TOOL_CONTENT_MAX_LENGTH);
    if (end > 0 && end < content.length() && Character.isHighSurrogate(content.charAt(end - 1))) {
      end--;
    }
    return content.substring(0, end);
  }

  private static final Instrumenter<AgentRequest, Void> AGENT_INSTRUMENTER =
      createAgentInstrumenter();
  private static final Instrumenter<ToolRequest, ToolCallResponse> TOOL_INSTRUMENTER =
      createToolInstrumenter();

  public static Instrumenter<AgentRequest, Void> agentInstrumenter() {
    return AGENT_INSTRUMENTER;
  }

  public static Instrumenter<ToolRequest, ToolCallResponse> toolInstrumenter() {
    return TOOL_INSTRUMENTER;
  }

  private static Instrumenter<AgentRequest, Void> createAgentInstrumenter() {
    return Instrumenter.<AgentRequest, Void>builder(
            GlobalOpenTelemetry.get(), INSTRUMENTATION_NAME, SpringAiAlibabaAgentSpanNames::agent)
        .addAttributesExtractor(new AgentAttributesExtractor())
        .buildInstrumenter(SpanKindExtractor.alwaysInternal());
  }

  private static Instrumenter<ToolRequest, ToolCallResponse> createToolInstrumenter() {
    InstrumenterBuilder<ToolRequest, ToolCallResponse> builder =
        Instrumenter.<ToolRequest, ToolCallResponse>builder(
                GlobalOpenTelemetry.get(),
                INSTRUMENTATION_NAME,
                SpringAiAlibabaAgentSpanNames::tool)
            .addAttributesExtractor(new ToolAttributesExtractor())
            .setSpanStatusExtractor(
                (spanStatusBuilder, request, response, error) -> {
                  if (response != null && response.isError()) {
                    spanStatusBuilder.setStatus(StatusCode.ERROR);
                  } else {
                    SpanStatusExtractor.getDefault()
                        .extract(spanStatusBuilder, request, response, error);
                  }
                });
    return builder.buildInstrumenter(SpanKindExtractor.alwaysInternal());
  }

  private static final class AgentAttributesExtractor
      implements AttributesExtractor<AgentRequest, Void> {
    @Override
    public void onStart(AttributesBuilder attributes, Context parentContext, AgentRequest request) {
      attributes.put(stringKey("gen_ai.agent.name"), request.getAgentName());
      attributes.put(stringKey("gen_ai.operation.name"), "invoke_agent");
    }

    @Override
    public void onEnd(
        AttributesBuilder attributes,
        Context context,
        AgentRequest request,
        @Nullable Void response,
        @Nullable Throwable error) {}
  }

  private static final class ToolAttributesExtractor
      implements AttributesExtractor<ToolRequest, ToolCallResponse> {
    @Override
    public void onStart(AttributesBuilder attributes, Context parentContext, ToolRequest request) {
      attributes.put(stringKey("gen_ai.operation.name"), "execute_tool");
      attributes.put(stringKey("gen_ai.agent.name"), request.getAgentName());
      attributes.put(stringKey("gen_ai.tool.name"), request.getToolName());
      attributes.put(stringKey("gen_ai.tool.call.id"), request.getToolCallId());
      if (CAPTURE_TOOL_CONTENT) {
        attributes.put(stringKey("gen_ai.tool.call.arguments"), request.getArguments());
        if (request.isArgumentsTruncated()) {
          attributes.put(booleanKey("gen_ai.tool.call.arguments.truncated"), true);
        }
      }
      attributes.put(
          booleanKey("spring_ai_alibaba.tool.parallel_execution"), request.isParallelExecution());
    }

    @Override
    public void onEnd(
        AttributesBuilder attributes,
        Context context,
        ToolRequest request,
        @Nullable ToolCallResponse response,
        @Nullable Throwable error) {
      if (CAPTURE_TOOL_CONTENT && response != null && !response.isError()) {
        String result = response.getResult();
        if (result != null) {
          attributes.put(stringKey("gen_ai.tool.call.result"), boundContent(result));
          if (result.length() > TOOL_CONTENT_MAX_LENGTH) {
            attributes.put(booleanKey("gen_ai.tool.call.result.truncated"), true);
          }
        }
      }
    }
  }

  private SpringAiAlibabaAgentSingletons() {}
}

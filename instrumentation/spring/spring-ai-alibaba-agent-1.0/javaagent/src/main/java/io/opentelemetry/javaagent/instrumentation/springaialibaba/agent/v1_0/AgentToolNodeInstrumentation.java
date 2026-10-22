/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.javaagent.instrumentation.springaialibaba.agent.v1_0;

import static io.opentelemetry.javaagent.instrumentation.springaialibaba.agent.v1_0.SpringAiAlibabaAgentSingletons.toolInstrumenter;
import static net.bytebuddy.matcher.ElementMatchers.isPrivate;
import static net.bytebuddy.matcher.ElementMatchers.named;
import static net.bytebuddy.matcher.ElementMatchers.returns;
import static net.bytebuddy.matcher.ElementMatchers.takesArgument;
import static net.bytebuddy.matcher.ElementMatchers.takesArguments;

import com.alibaba.cloud.ai.graph.agent.interceptor.ToolCallResponse;
import io.opentelemetry.context.Context;
import io.opentelemetry.context.Scope;
import io.opentelemetry.javaagent.extension.instrumentation.TypeInstrumentation;
import io.opentelemetry.javaagent.extension.instrumentation.TypeTransformer;
import javax.annotation.Nullable;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.matcher.ElementMatcher;

class AgentToolNodeInstrumentation implements TypeInstrumentation {
  @Override
  public ElementMatcher<TypeDescription> typeMatcher() {
    return named("com.alibaba.cloud.ai.graph.agent.node.AgentToolNode");
  }

  @Override
  public void transform(TypeTransformer transformer) {
    transformer.applyAdviceToMethod(
        named("executeToolCallWithInterceptors")
            .and(isPrivate())
            .and(takesArguments(7))
            .and(
                takesArgument(
                    0, named("org.springframework.ai.chat.messages.AssistantMessage$ToolCall")))
            .and(takesArgument(4, boolean.class))
            .and(returns(named("com.alibaba.cloud.ai.graph.agent.interceptor.ToolCallResponse"))),
        getClass().getName() + "$ToolCallAdvice");
  }

  @SuppressWarnings("unused")
  public static class ToolCallAdvice {
    public static class AdviceScope {
      private final ToolRequest request;
      private final Context context;
      private final Scope scope;

      private AdviceScope(ToolRequest request, Context context) {
        this.request = request;
        this.context = context;
        this.scope = context.makeCurrent();
      }

      @Nullable
      public static AdviceScope start(ToolRequest request) {
        Context parent = Context.current();
        if (!toolInstrumenter().shouldStart(parent, request)) {
          return null;
        }
        return new AdviceScope(request, toolInstrumenter().start(parent, request));
      }

      public void end(@Nullable ToolCallResponse response, @Nullable Throwable error) {
        scope.close();
        toolInstrumenter().end(context, request, response, error);
      }
    }

    @Advice.OnMethodEnter(suppress = Throwable.class, inline = false)
    @Nullable
    public static AdviceScope onEnter(
        @Advice.FieldValue("agentName") String agentName,
        @Advice.Argument(0) Object toolCall,
        @Advice.Argument(4) boolean parallelExecution) {
      return AdviceScope.start(new ToolRequest(agentName, toolCall, parallelExecution));
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class, inline = false)
    public static void onExit(
        @Advice.Enter @Nullable AdviceScope scope,
        @Advice.Return @Nullable ToolCallResponse response,
        @Advice.Thrown @Nullable Throwable error) {
      if (scope != null) {
        scope.end(response, error);
      }
    }
  }
}

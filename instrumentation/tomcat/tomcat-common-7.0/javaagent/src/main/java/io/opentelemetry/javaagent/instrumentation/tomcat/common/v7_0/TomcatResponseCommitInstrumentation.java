/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.javaagent.instrumentation.tomcat.common.v7_0;

import static net.bytebuddy.matcher.ElementMatchers.named;
import static net.bytebuddy.matcher.ElementMatchers.takesArguments;

import io.opentelemetry.context.Context;
import io.opentelemetry.javaagent.bootstrap.http.HttpServerResponseCustomizerHolder;
import io.opentelemetry.javaagent.extension.instrumentation.TypeInstrumentation;
import io.opentelemetry.javaagent.extension.instrumentation.TypeTransformer;
import io.opentelemetry.javaagent.instrumentation.servlet.common.ServletHelper;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.matcher.ElementMatcher;
import org.apache.coyote.ActionCode;
import org.apache.coyote.Response;

public class TomcatResponseCommitInstrumentation implements TypeInstrumentation {
  @Override
  public ElementMatcher<TypeDescription> typeMatcher() {
    return named("org.apache.coyote.Response");
  }

  @Override
  public void transform(TypeTransformer transformer) {
    transformer.applyAdviceToMethod(
        named("action").and(takesArguments(2)), getClass().getName() + "$CommitAdvice");
  }

  @SuppressWarnings("unused")
  public static class CommitAdvice {
    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static void onEnter(
        @Advice.This Response response, @Advice.Argument(0) ActionCode action) {
      if (action == ActionCode.COMMIT && !response.isCommitted() && response.getRequest() != null) {
        Object context = response.getRequest().getAttribute(ServletHelper.CONTEXT_ATTRIBUTE);
        if (context instanceof Context) {
          HttpServerResponseCustomizerHolder.getCustomizer()
              .customizeBeforeCommit(
                  (Context) context, response, TomcatCommitResponseMutator.INSTANCE);
        }
      }
    }
  }
}

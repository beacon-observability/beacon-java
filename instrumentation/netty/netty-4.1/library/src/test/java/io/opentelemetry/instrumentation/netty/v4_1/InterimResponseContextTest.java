/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.instrumentation.netty.v4_1;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;

import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.handler.codec.http.DefaultFullHttpResponse;
import io.netty.handler.codec.http.DefaultHttpRequest;
import io.netty.handler.codec.http.DefaultHttpResponse;
import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.codec.http.HttpResponse;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.HttpVersion;
import io.netty.handler.codec.http.LastHttpContent;
import io.opentelemetry.context.Context;
import io.opentelemetry.instrumentation.api.instrumenter.Instrumenter;
import io.opentelemetry.instrumentation.netty.common.v4_0.internal.NettyCommonRequest;
import io.opentelemetry.instrumentation.netty.v4_1.internal.ProtocolEventHandler;
import io.opentelemetry.instrumentation.netty.v4_1.internal.ServerContext;
import io.opentelemetry.instrumentation.netty.v4_1.internal.ServerContexts;
import io.opentelemetry.instrumentation.netty.v4_1.internal.server.HttpServerResponseBeforeCommitHandler;
import io.opentelemetry.instrumentation.netty.v4_1.internal.server.HttpServerResponseTracingHandler;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class InterimResponseContextTest {
  @ParameterizedTest
  @ValueSource(booleans = {true, false})
  @SuppressWarnings("unchecked")
  void interimResponsePreservesCallbackAndRequestContext(boolean full) {
    Instrumenter<NettyCommonRequest, HttpResponse> instrumenter = mock(Instrumenter.class);
    HttpServerResponseBeforeCommitHandler beforeCommit =
        mock(HttpServerResponseBeforeCommitHandler.class);
    EmbeddedChannel channel =
        new EmbeddedChannel(
            new HttpServerResponseTracingHandler(
                instrumenter, beforeCommit, ProtocolEventHandler.Noop.INSTANCE));
    try {
      Context context = Context.root();
      NettyCommonRequest request =
          NettyCommonRequest.create(
              new DefaultHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.GET, "/"), channel);
      ServerContext serverContext = ServerContext.create(context, request);
      ServerContexts contexts = ServerContexts.getOrCreate(channel);
      contexts.addLast(serverContext);
      for (HttpResponseStatus status :
          new HttpResponseStatus[] {
            HttpResponseStatus.CONTINUE, new HttpResponseStatus(103, "Early Hints")
          }) {
        HttpResponse interim =
            full
                ? new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, status)
                : new DefaultHttpResponse(HttpVersion.HTTP_1_1, status);
        channel.writeOutbound(interim);
        if (!full) {
          channel.writeOutbound(LastHttpContent.EMPTY_LAST_CONTENT);
        }
        verify(beforeCommit).handle(context, interim);
        assertThat(contexts.peekFirst()).isSameAs(serverContext);
        verifyNoInteractions(instrumenter);
      }

      HttpResponse response =
          new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK);
      channel.writeOutbound(response);
      verify(beforeCommit).handle(context, response);
      verifyNoMoreInteractions(beforeCommit);
      verify(instrumenter).end(context, request, response, null);
      assertThat(contexts.peekFirst()).isNull();
    } finally {
      channel.finishAndReleaseAll();
    }
  }
}

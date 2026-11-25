/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.instrumentation.netty.v4_1.internal.server;

import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelOutboundHandlerAdapter;
import io.netty.channel.ChannelPromise;
import io.netty.handler.codec.http.FullHttpResponse;
import io.netty.handler.codec.http.HttpResponse;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.LastHttpContent;
import io.netty.util.AttributeKey;
import io.opentelemetry.context.Context;
import io.opentelemetry.context.Scope;
import io.opentelemetry.instrumentation.api.instrumenter.Instrumenter;
import io.opentelemetry.instrumentation.netty.common.internal.NettyErrorHolder;
import io.opentelemetry.instrumentation.netty.common.v4_0.internal.NettyCommonRequest;
import io.opentelemetry.instrumentation.netty.v4_1.internal.ProtocolEventHandler;
import io.opentelemetry.instrumentation.netty.v4_1.internal.ProtocolSpecificEvent;
import io.opentelemetry.instrumentation.netty.v4_1.internal.ServerContext;
import io.opentelemetry.instrumentation.netty.v4_1.internal.ServerContexts;
import javax.annotation.Nullable;

/**
 * This class is internal and is hence not for public use. Its APIs are unstable and can change at
 * any time.
 */
public class HttpServerResponseTracingHandler extends ChannelOutboundHandlerAdapter {

  private static final AttributeKey<HttpResponse> HTTP_SERVER_RESPONSE =
      AttributeKey.valueOf(HttpServerResponseTracingHandler.class, "http-server-response");

  private final Instrumenter<NettyCommonRequest, HttpResponse> instrumenter;
  private final HttpServerResponseBeforeCommitHandler beforeCommitHandler;
  private final ProtocolEventHandler eventHandler;

  public HttpServerResponseTracingHandler(
      Instrumenter<NettyCommonRequest, HttpResponse> instrumenter,
      HttpServerResponseBeforeCommitHandler beforeCommitHandler,
      ProtocolEventHandler eventHandler) {
    this.instrumenter = instrumenter;
    this.beforeCommitHandler = beforeCommitHandler;
    this.eventHandler = eventHandler;
  }

  @Override
  public void write(ChannelHandlerContext ctx, Object msg, ChannelPromise prm) throws Exception {
    ServerContexts serverContexts = ServerContexts.get(ctx.channel());
    ServerContext serverContext = serverContexts != null ? serverContexts.peekFirst() : null;
    if (serverContext == null) {
      super.write(ctx, msg, prm);
      return;
    }

    // Interim responses must retain the request context for the final response.
    if (msg instanceof HttpResponse) {
      HttpResponse response = (HttpResponse) msg;
      int status = response.status().code();
      if (status >= 100 && status < 200 && status != 101) {
        // Keep the existing SPI callback, even when response trace ID injection is disabled.
        beforeCommitHandler.handle(serverContext.context(), response);
        if (!(msg instanceof FullHttpResponse)) {
          ctx.channel().attr(HTTP_SERVER_RESPONSE).set(response);
        }
        writeInterim(ctx, msg, prm, serverContexts, serverContext);
        return;
      }
    } else if (msg instanceof LastHttpContent) {
      HttpResponse previous = ctx.channel().attr(HTTP_SERVER_RESPONSE).get();
      if (previous != null
          && previous.status().code() >= 100
          && previous.status().code() < 200
          && previous.status().code() != 101) {
        ctx.channel().attr(HTTP_SERVER_RESPONSE).set(null);
        writeInterim(ctx, msg, prm, serverContexts, serverContext);
        return;
      }
    }

    ChannelPromise writePromise;

    if (msg instanceof LastHttpContent) {
      if (prm.isVoid()) {
        // Some frameworks don't actually listen for response completion and optimize for
        // allocations by using a singleton, unnotifiable promise. Hopefully these frameworks don't
        // have observability features or they'd be way off...
        writePromise = ctx.newPromise();
      } else {
        writePromise = prm;
      }

      // Going to finish the span after the write of the last content finishes.
      if (msg instanceof FullHttpResponse) {
        FullHttpResponse response = (FullHttpResponse) msg;
        ctx.channel().attr(HTTP_SERVER_RESPONSE).set(null);
        if (response.status().equals(HttpResponseStatus.SWITCHING_PROTOCOLS)) {
          eventHandler.handle(
              ProtocolSpecificEvent.SWITCHING_PROTOCOLS,
              serverContext.context(),
              serverContext.request().getRequest(),
              response);
        } else {
          // Headers and body all sent together, we have the response information in the msg.
          beforeCommitHandler.handle(serverContext.context(), (HttpResponse) msg);
          serverContexts.pollFirst();
          writePromise.addListener(
              future ->
                  end(
                      serverContext.context(),
                      serverContext.request(),
                      (FullHttpResponse) msg,
                      writePromise));
        }
      } else {
        HttpResponse responseTest = ctx.channel().attr(HTTP_SERVER_RESPONSE).get();
        if (responseTest == null
            || !responseTest.status().equals(HttpResponseStatus.SWITCHING_PROTOCOLS)) {
          // Body sent after headers. We stored the response information in the context when
          // encountering HttpResponse (which was not FullHttpResponse since it's not
          // LastHttpContent).
          serverContexts.pollFirst();
          HttpResponse response = ctx.channel().attr(HTTP_SERVER_RESPONSE).getAndSet(null);
          writePromise.addListener(
              future ->
                  end(serverContext.context(), serverContext.request(), response, writePromise));
        }
      }
    } else {
      writePromise = prm;
      if (msg instanceof HttpResponse) {
        HttpResponse response = (HttpResponse) msg;
        if (response.status().equals(HttpResponseStatus.SWITCHING_PROTOCOLS)) {
          eventHandler.handle(
              ProtocolSpecificEvent.SWITCHING_PROTOCOLS,
              serverContext.context(),
              serverContext.request().getRequest(),
              response);
        } else {
          // Headers before body has been sent, store them to use when finishing the span.
          beforeCommitHandler.handle(serverContext.context(), response);
          ctx.channel().attr(HTTP_SERVER_RESPONSE).set(response);
        }
      }
    }

    try (Scope ignored = serverContext.context().makeCurrent()) {
      super.write(ctx, msg, writePromise);
    } catch (Throwable t) {
      serverContexts.pollFirst();
      end(serverContext.context(), serverContext.request(), null, t);
      throw t;
    }
  }

  private void writeInterim(
      ChannelHandlerContext ctx,
      Object msg,
      ChannelPromise promise,
      ServerContexts contexts,
      ServerContext context)
      throws Exception {
    try (Scope ignored = context.context().makeCurrent()) {
      super.write(ctx, msg, promise);
    } catch (Throwable t) {
      contexts.pollFirst();
      ctx.channel().attr(HTTP_SERVER_RESPONSE).set(null);
      end(context.context(), context.request(), null, t);
      throw t;
    }
  }

  private void end(
      Context context, NettyCommonRequest request, HttpResponse response, ChannelFuture future) {
    Throwable error = future.isSuccess() ? null : future.cause();
    end(context, request, response, error);
  }

  private void end(
      Context context,
      NettyCommonRequest request,
      @Nullable HttpResponse response,
      @Nullable Throwable error) {
    error = NettyErrorHolder.getOrDefault(context, error);
    instrumenter.end(context, request, response, error);
  }
}

/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

import io.netty.bootstrap.ServerBootstrap;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.handler.codec.http.DefaultFullHttpResponse;
import io.netty.handler.codec.http.DefaultHttpResponse;
import io.netty.handler.codec.http.DefaultLastHttpContent;
import io.netty.handler.codec.http.HttpRequest;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.HttpServerCodec;
import io.netty.handler.codec.http.HttpVersion;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.concurrent.TimeUnit;
import org.apache.catalina.Context;
import org.apache.catalina.startup.Tomcat;

public class ResponseTraceIdServer {
  public static void main(String[] args) throws Exception {
    if (args[0].equals("netty")) {
      netty();
    } else {
      tomcat();
    }
  }

  private static void netty() throws Exception {
    NioEventLoopGroup boss = new NioEventLoopGroup(1);
    NioEventLoopGroup workers = new NioEventLoopGroup(2);
    Channel channel =
        new ServerBootstrap()
            .group(boss, workers)
            .channel(NioServerSocketChannel.class)
            .childHandler(
                new ChannelInitializer<SocketChannel>() {
                  @Override
                  protected void initChannel(SocketChannel channel) {
                    channel.pipeline().addLast(new HttpServerCodec());
                    channel.pipeline().addLast(
                        new ChannelInboundHandlerAdapter() {
                          @Override
                          public void channelRead(ChannelHandlerContext ctx, Object msg) {
                            if (!(msg instanceof HttpRequest)) {
                              io.netty.util.ReferenceCountUtil.release(msg);
                              return;
                            }
                            String path = ((HttpRequest) msg).uri();
                            Runnable write = () -> respond(ctx, path);
                            if (path.contains("async")) {
                              ctx.executor().schedule(write, 10, TimeUnit.MILLISECONDS);
                            } else {
                              write.run();
                            }
                          }
                        });
                  }
                })
            .bind("127.0.0.1", 0)
            .sync()
            .channel();
    System.out.println("PORT=" + ((java.net.InetSocketAddress) channel.localAddress()).getPort());
    System.out.flush();
    channel.closeFuture().sync();
  }

  private static void respond(ChannelHandlerContext ctx, String path) {
    if (path.contains("interim")) {
      ctx.write(new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.CONTINUE));
    }
    HttpResponseStatus status =
        path.contains("error") ? HttpResponseStatus.INTERNAL_SERVER_ERROR : HttpResponseStatus.OK;
    byte[] body = (path.contains("error") ? "error" : "ok").getBytes(StandardCharsets.UTF_8);
    io.netty.handler.codec.http.HttpResponse response =
        path.contains("chunked")
            ? new DefaultHttpResponse(HttpVersion.HTTP_1_1, status)
            : new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, status, Unpooled.wrappedBuffer(body));
    response.headers().set("Content-Length", body.length);
    if (path.contains("existing")) {
      response.headers().add(headerName().toUpperCase(java.util.Locale.ROOT), "application-one");
      response
          .headers()
          .add(headerName().toLowerCase(java.util.Locale.ROOT), "application-two");
    }
    ctx.write(response);
    if (path.contains("chunked")) {
      ctx.write(new DefaultLastHttpContent(Unpooled.wrappedBuffer(body)));
    }
    ctx.flush();
  }

  private static String headerName() {
    String name =
        System.getProperty(
            "otel.instrumentation.common.http.server.response-trace-id.header-name", "btrace-id");
    return name.equals("bad:name") ? "btrace-id" : name;
  }

  private static void tomcat() throws Exception {
    Tomcat tomcat = new Tomcat();
    tomcat.setBaseDir(Files.createTempDirectory("trace-id-tomcat").toString());
    tomcat.setPort(0);
    tomcat.getConnector();
    Context context = tomcat.addContext("", Files.createTempDirectory("trace-id-app").toString());
    String namespace;
    try {
      Class.forName("jakarta.servlet.Servlet");
      namespace = "jakarta.servlet.";
    } catch (ClassNotFoundException e) {
      namespace = "javax.servlet.";
    }
    Class<?> servlet = Class.forName(namespace + "Servlet");
    Class<?> requestType = Class.forName(namespace + "ServletRequest");
    Class<?> responseType = Class.forName(namespace + "ServletResponse");
    Class<?> httpRequest = Class.forName(namespace + "http.HttpServletRequest");
    Class<?> httpResponse = Class.forName(namespace + "http.HttpServletResponse");
    Class<?> asyncType = Class.forName(namespace + "AsyncContext");
    Object handler =
        Proxy.newProxyInstance(
            servlet.getClassLoader(),
            new Class<?>[] {servlet},
            (proxy, method, args) -> {
              if (!method.getName().equals("service")) {
                return null;
              }
              Object request = args[0];
              Object response = args[1];
              String path = (String) httpRequest.getMethod("getRequestURI").invoke(request);
              if (path.contains("reset")) {
                httpResponse.getMethod("setHeader", String.class, String.class)
                    .invoke(response, "temporary", "removed");
                responseType.getMethod("reset").invoke(response);
              }
              if (path.contains("existing")) {
                Method add = httpResponse.getMethod("addHeader", String.class, String.class);
                add.invoke(
                    response, headerName().toUpperCase(java.util.Locale.ROOT), "application-one");
                add.invoke(
                    response, headerName().toLowerCase(java.util.Locale.ROOT), "application-two");
              }
              if (path.contains("error")) {
                httpResponse.getMethod("sendError", int.class).invoke(response, 500);
              } else if (path.contains("async")) {
                Object async = requestType.getMethod("startAsync").invoke(request);
                asyncType.getMethod("start", Runnable.class)
                    .invoke(
                        async,
                        (Runnable) () -> {
                          try {
                            java.io.PrintWriter writer =
                                (java.io.PrintWriter)
                                    responseType.getMethod("getWriter").invoke(response);
                            writer.write("ok");
                            asyncType.getMethod("complete").invoke(async);
                          } catch (ReflectiveOperationException e) {
                            throw new IllegalStateException(e);
                          }
                        });
              } else {
                java.io.PrintWriter writer =
                    (java.io.PrintWriter) responseType.getMethod("getWriter").invoke(response);
                writer.write("ok");
              }
              return null;
            });
    Object wrapper =
        Tomcat.class.getMethod("addServlet", Context.class, String.class, servlet)
            .invoke(null, context, "test", handler);
    wrapper.getClass().getMethod("setAsyncSupported", boolean.class).invoke(wrapper, true);
    context.addServletMappingDecoded("/*", "test");
    org.apache.tomcat.util.descriptor.web.ErrorPage errorPage =
        new org.apache.tomcat.util.descriptor.web.ErrorPage();
    errorPage.setErrorCode(500);
    errorPage.setLocation("/dispatched");
    context.addErrorPage(errorPage);
    tomcat.start();
    System.out.println("PORT=" + tomcat.getConnector().getLocalPort());
    System.out.flush();
    tomcat.getServer().await();
  }
}

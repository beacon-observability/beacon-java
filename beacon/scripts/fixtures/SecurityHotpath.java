// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package beacon.benchmark;

import com.sun.management.ThreadMXBean;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.lang.management.ManagementFactory;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class SecurityHotpath {
  private static final ThreadMXBean THREADS = (ThreadMXBean) ManagementFactory.getThreadMXBean();
  private static volatile long consumed;
  private static final int ITERATIONS = 100000;

  public static void main(String[] args) throws Exception {
    if (THREADS.isThreadAllocatedMemorySupported()) {
      THREADS.setThreadAllocatedMemoryEnabled(true);
    }
    for (int i = 0; i < 10; i++) {
      loop(ITERATIONS);
    }
    System.out.println("INACTIVE " + measure());
    HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    ExecutorService executor = Executors.newSingleThreadExecutor();
    server.setExecutor(executor);
    server.createContext("/bench", new Handler());
    Runtime.getRuntime()
        .addShutdownHook(
            new Thread(
                () -> {
                  server.stop(0);
                  executor.shutdownNow();
                }));
    server.start();
    System.out.println("PORT " + server.getAddress().getPort());
    new CountDownLatch(1).await();
  }

  private static String measure() {
    long id = Thread.currentThread().getId();
    long beforeBytes = THREADS.getThreadAllocatedBytes(id);
    long before = System.nanoTime();
    loop(ITERATIONS);
    long elapsed = System.nanoTime() - before;
    long allocated = THREADS.getThreadAllocatedBytes(id) - beforeBytes;
    return "{\"iterations\":"
        + ITERATIONS
        + ",\"nanos\":"
        + elapsed
        + ",\"allocated_bytes\":"
        + allocated
        + ",\"checksum\":"
        + consumed
        + "}";
  }

  private static void loop(int count) {
    StringBuilder value = new StringBuilder(32);
    long sum = 0;
    for (int i = 0; i < count; i++) {
      value.setLength(0);
      value.append(10000 + (i & 1023));
      sum += value.length();
    }
    consumed = sum;
  }

  private static class Handler implements HttpHandler {
    @Override
    public void handle(HttpExchange exchange) throws IOException {
      byte[] body = measure().getBytes(StandardCharsets.UTF_8);
      exchange.sendResponseHeaders(200, body.length);
      try {
        exchange.getResponseBody().write(body);
      } finally {
        exchange.close();
      }
    }
  }
}

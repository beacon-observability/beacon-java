/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

public class ResponseTraceIdAcceptance {
  public static void main(String[] args) throws Exception {
    for (String server : new String[] {"tomcat", "netty"}) {
      check(args[0], server, null, "btrace-id", false);
      check(args[0], server, false, "btrace-id", false);
      check(args[0], server, true, "btrace-id", false);
      check(args[0], server, true, "x-trace", false);
      check(args[0], server, true, "bad:name", false);
      check(args[0], server, true, "btrace-id", true);
    }
  }

  private static void check(
      String agent, String server, Boolean enabled, String header, boolean unsampled)
      throws Exception {
    List<String> command = new ArrayList<>();
    command.add(System.getProperty("java.home") + "/bin/java");
    command.add("-javaagent:" + agent);
    command.add("-Dotel.traces.exporter=none");
    command.add("-Dotel.metrics.exporter=none");
    command.add("-Dotel.logs.exporter=none");
    // Null intentionally omits the property to exercise the packaged agent's default.
    if (enabled != null) {
      command.add("-Dotel.instrumentation.common.http.server.response-trace-id.enabled=" + enabled);
    }
    if (!header.equals("btrace-id")) {
      command.add(
          "-Dotel.instrumentation.common.http.server.response-trace-id.header-name=" + header);
    }
    if (unsampled) {
      command.add("-Dotel.traces.sampler=always_off");
    }
    command.add("-cp");
    command.add(System.getProperty("java.class.path"));
    command.add("ResponseTraceIdServer");
    command.add(server);
    ProcessBuilder builder =
        new ProcessBuilder(command).redirectError(ProcessBuilder.Redirect.INHERIT);
    // Parent environment must not turn the unconfigured-default scenario into an enabled one.
    builder
        .environment()
        .remove("OTEL_INSTRUMENTATION_COMMON_HTTP_SERVER_RESPONSE_TRACE_ID_ENABLED");
    builder
        .environment()
        .remove("OTEL_INSTRUMENTATION_COMMON_HTTP_SERVER_RESPONSE_TRACE_ID_HEADER_NAME");
    Process process = builder.start();
    try {
      CompletableFuture<Integer> port =
          CompletableFuture.supplyAsync(
              () -> {
                try {
                  BufferedReader reader =
                      new BufferedReader(new InputStreamReader(process.getInputStream()));
                  String line;
                  while ((line = reader.readLine()) != null) {
                    System.out.println(line);
                    if (line.startsWith("PORT=")) {
                      return Integer.parseInt(line.substring(5));
                    }
                  }
                  throw new IllegalStateException("Server exited without a port");
                } catch (java.io.IOException e) {
                  throw new IllegalStateException(e);
                }
              });
      int serverPort = port.get(90, TimeUnit.SECONDS);
      HttpClient client =
          HttpClient.newBuilder()
              .version(HttpClient.Version.HTTP_1_1)
              .connectTimeout(Duration.ofSeconds(10))
              .build();
      String[] paths =
          server.equals("tomcat")
              ? new String[] {
                "/ok",
                "/existing",
                "/reset",
                "/reset-error",
                "/reset-async",
                "/reset-async-existing"
              }
              : new String[] {"/ok", "/existing", "/error", "/async", "/chunked", "/interim"};
      List<CompletableFuture<Void>> requests = new ArrayList<>();
      // Reuse one client for concurrent requests and subsequent persistent-connection requests.
      for (int round = 0; round < 2; round++) {
        for (int i = 1; i <= 24; i++) {
          String trace = String.format("%032x", round * 24 + i);
          String path = paths[(i - 1) % paths.length];
          HttpRequest request =
              HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + serverPort + path))
                  .timeout(Duration.ofSeconds(20))
                  .header(
                      "traceparent",
                      "00-" + trace + "-0000000000000001-" + (unsampled ? "00" : "01"))
                  .build();
          requests.add(
              client.sendAsync(request, HttpResponse.BodyHandlers.ofString())
                  .thenAccept(
                      response -> {
                        int expectedStatus = path.contains("error") ? 500 : 200;
                        require(
                            response.statusCode() == expectedStatus,
                            "status " + response.statusCode());
                        String body =
                            expectedStatus == 500 && server.equals("netty") ? "error" : "ok";
                        require(response.body().equals(body), "body " + response.body());
                        require(
                            response.headers().allValues("temporary").isEmpty(), "reset failed");
                        String key = header.equals("bad:name") ? "btrace-id" : header;
                        List<String> values = response.headers().allValues(key);
                        if (path.contains("existing")) {
                          require(
                              values.equals(List.of("application-one", "application-two")),
                              "application headers " + values);
                        } else {
                          require(
                              values.equals(
                                  Boolean.TRUE.equals(enabled) && !header.equals("bad:name")
                                      ? List.of(trace)
                                      : List.of()),
                              server + " " + path + " expected " + trace + " got " + values);
                        }
                        if (!key.equals("btrace-id")) {
                          require(
                              response.headers().allValues("btrace-id").isEmpty(),
                              "unexpected default header with custom name");
                        }
                      }));
        }
        CompletableFuture.allOf(requests.toArray(new CompletableFuture<?>[0])).join();
        requests.clear();
      }
      System.out.println(
          "PASS "
              + server
              + " enabled="
              + (enabled == null ? "unconfigured" : enabled)
              + " header="
              + header
              + " unsampled="
              + unsampled);
    } finally {
      process.destroy();
      if (!process.waitFor(10, TimeUnit.SECONDS)) {
        process.destroyForcibly();
        process.waitFor();
      }
    }
  }

  private static void require(boolean condition, String message) {
    if (!condition) {
      throw new AssertionError(message);
    }
  }
}

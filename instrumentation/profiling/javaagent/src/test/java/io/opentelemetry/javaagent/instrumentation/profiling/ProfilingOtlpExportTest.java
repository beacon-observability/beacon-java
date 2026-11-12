/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.javaagent.instrumentation.profiling;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import io.grpc.Server;
import io.grpc.netty.shaded.io.grpc.netty.NettyServerBuilder;
import io.grpc.stub.StreamObserver;
import io.opentelemetry.proto.collector.profiles.v1development.ExportProfilesServiceRequest;
import io.opentelemetry.proto.collector.profiles.v1development.ExportProfilesServiceResponse;
import io.opentelemetry.proto.collector.profiles.v1development.ProfilesServiceGrpc;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class ProfilingOtlpExportTest {

  private static HttpServer server;
  private static Server grpcServer;
  private static AtomicReference<String> requestContentType;
  private static AtomicReference<byte[]> requestBody;

  @BeforeAll
  static void setUp() throws Exception {
    Class<?> flightRecorderClass = Class.forName("jdk.jfr.FlightRecorder");
    boolean available = (Boolean) flightRecorderClass.getMethod("isAvailable").invoke(null);
    Assumptions.assumeTrue(available, "JFR not available");

    requestContentType = new AtomicReference<>();
    requestBody = new AtomicReference<>();

    int port = Integer.parseInt(System.getProperty("profiling.otlp.test.port"));
    if ("grpc".equals(System.getProperty("profiling.otlp.test.protocol"))) {
      grpcServer =
          NettyServerBuilder.forAddress(
                  new InetSocketAddress(InetAddress.getLoopbackAddress(), port))
              .addService(
                  new ProfilesServiceGrpc.ProfilesServiceImplBase() {
                    @Override
                    public void export(
                        ExportProfilesServiceRequest value,
                        StreamObserver<ExportProfilesServiceResponse> observer) {
                      requestBody.set(value.toByteArray());
                      observer.onNext(ExportProfilesServiceResponse.getDefaultInstance());
                      observer.onCompleted();
                    }
                  })
              .build()
              .start();
    } else {
      server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), port), 0);
      server.createContext(
          "/v1development/profiles",
          exchange -> {
            requestContentType.set(exchange.getRequestHeaders().getFirst("Content-Type"));
            requestBody.set(readBody(exchange));
            byte[] response = new byte[0];
            exchange.sendResponseHeaders(200, -1);
            try {
              exchange.getResponseBody().write(response);
            } finally {
              exchange.close();
            }
          });
      server.start();
    }
  }

  @AfterAll
  static void tearDown() {
    if (grpcServer != null) {
      grpcServer.shutdownNow();
    }
    if (server != null) {
      server.stop(0);
    }
  }

  @Test
  void shouldExportProfilesToOtlpEndpoint() {
    await()
        .atMost(Duration.ofSeconds(20))
        .untilAsserted(
            () -> {
              doBusyWork(Duration.ofMillis(250));

              if (!"grpc".equals(System.getProperty("profiling.otlp.test.protocol"))) {
                assertThat(requestContentType.get()).isEqualTo("application/x-protobuf");
              }
              assertThat(requestBody.get()).isNotNull();
              var request = ExportProfilesServiceRequest.parseFrom(requestBody.get());
              assertThat(request.getDictionary().getStackTableCount()).isGreaterThan(1);
              var resource = request.getResourceProfiles(0);
              assertThat(resource.getResource().getAttributesList())
                  .anySatisfy(
                      attribute -> {
                        assertThat(attribute.getKey()).isEqualTo("service.name");
                        assertThat(attribute.getValue().getStringValue())
                            .isEqualTo("profiling-test-service");
                      });
              assertThat(resource.getScopeProfiles(0).getProfilesList())
                  .anySatisfy(
                      profile -> {
                        assertThat(profile.getSamplesCount()).isPositive();
                        assertThat(profile.getOriginalPayload()).isEmpty();
                      });
            });
  }

  private static byte[] readBody(HttpExchange exchange) throws IOException {
    try (InputStream inputStream = exchange.getRequestBody();
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
      byte[] buffer = new byte[1024];
      int read;
      while ((read = inputStream.read(buffer)) >= 0) {
        outputStream.write(buffer, 0, read);
      }
      return outputStream.toByteArray();
    }
  }

  private static void doBusyWork(Duration duration) {
    long end = System.nanoTime() + duration.toNanos();
    long state = 1;
    while (System.nanoTime() < end) {
      state = state * 1664525L + 1013904223L;
    }
    if (state == Long.MIN_VALUE) {
      throw new AssertionError("Unreachable");
    }
  }
}

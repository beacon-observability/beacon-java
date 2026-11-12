/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.instrumentation.profiling.internal;

import static java.util.Collections.emptyMap;
import static java.util.Collections.singletonMap;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

import com.sun.net.httpserver.HttpServer;
import io.github.netmikey.logunit.api.LogCapturer;
import io.grpc.Server;
import io.grpc.netty.shaded.io.grpc.netty.NettyServerBuilder;
import io.grpc.stub.StreamObserver;
import io.opentelemetry.api.common.Attributes;
import io.opentelemetry.instrumentation.profiling.ProfileSnapshot;
import io.opentelemetry.proto.collector.profiles.v1development.ExportProfilesPartialSuccess;
import io.opentelemetry.proto.collector.profiles.v1development.ExportProfilesServiceRequest;
import io.opentelemetry.proto.collector.profiles.v1development.ExportProfilesServiceResponse;
import io.opentelemetry.proto.collector.profiles.v1development.ProfilesServiceGrpc;
import io.opentelemetry.sdk.resources.Resource;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URL;
import java.nio.file.Path;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicReference;
import jdk.jfr.Recording;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class OtlpProfileExporterAdapterTest {
  @RegisterExtension
  LogCapturer logs = LogCapturer.create().captureForType(OtlpProfileExporterAdapter.class);

  @TempDir Path directory;
  private static volatile double busyResult;

  private JfrFileSnapshot recording() throws Exception {
    Path path = directory.resolve("profile.jfr");
    try (Recording recording = new Recording()) {
      recording.enable("jdk.ExecutionSample").withPeriod(Duration.ofMillis(1)).withStackTrace();
      recording.start();
      long deadline = System.nanoTime() + Duration.ofSeconds(2).toNanos();
      double result = 1;
      while (System.nanoTime() < deadline) {
        result = Math.log(result + 1.5);
      }
      busyResult = result;
      assertThat(busyResult).isGreaterThan(0);
      recording.stop();
      recording.dump(path);
      return new JfrFileSnapshot(path, recording.getStartTime(), recording.getStopTime());
    }
  }

  private static void verify(ExportProfilesServiceRequest request) {
    var dictionary = request.getDictionary();
    assertThat(dictionary.getStringTable(0)).isEmpty();
    assertThat(dictionary.getStackTableCount()).isGreaterThan(1);
    assertThat(dictionary.getStringTableList())
        .anyMatch(name -> name.contains("OtlpProfileExporterAdapterTest"));
    var resource = request.getResourceProfiles(0);
    assertThat(resource.getResource().getAttributesList())
        .anySatisfy(
            attribute -> {
              assertThat(attribute.getKey()).isEqualTo("service.name");
              assertThat(attribute.getValue().getStringValue()).isEqualTo("checkout");
            });
    var profile = resource.getScopeProfiles(0).getProfiles(0);
    assertThat(profile.getSamplesCount()).isPositive();
    assertThat(profile.getOriginalPayload()).isEmpty();
    assertThat(profile.getProfileId().size()).isEqualTo(16);
    assertThat(dictionary.getStringTable(profile.getSampleType().getUnitStrindex()))
        .isEqualTo("count");
    profile
        .getSamplesList()
        .forEach(
            sample -> {
              assertThat(sample.getValues(0)).isEqualTo(1);
              assertThat(sample.getStackIndex()).isBetween(1, dictionary.getStackTableCount() - 1);
              assertThat(sample.getTimestampsUnixNano(0))
                  .isGreaterThanOrEqualTo(profile.getTimeUnixNano());
            });
  }

  private static ExportProfilesServiceResponse response(boolean partialRejection) {
    return partialRejection
        ? ExportProfilesServiceResponse.newBuilder()
            .setPartialSuccess(
                ExportProfilesPartialSuccess.newBuilder()
                    .setRejectedProfiles(1)
                    .setErrorMessage("rejected allocation profile"))
            .build()
        : ExportProfilesServiceResponse.getDefaultInstance();
  }

  @Test
  void emptySnapshotsDoNotConnect() throws Exception {
    for (String protocol : new String[] {"http/protobuf", "grpc"}) {
      new OtlpProfileExporterAdapter(
              new URL("http://127.0.0.1:1"),
              protocol,
              Duration.ofSeconds(1),
              emptyMap(),
              Resource.empty())
          .export(mock(ProfileSnapshot.class));
    }
  }

  @ParameterizedTest
  @ValueSource(booleans = {false, true})
  void exportsDecodedProfilesOverHttp(boolean partialRejection) throws Exception {
    AtomicReference<ExportProfilesServiceRequest> request = new AtomicReference<>();
    HttpServer server =
        HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
    server.createContext(
        "/v1development/profiles",
        exchange -> {
          assertThat(exchange.getRequestHeaders().getFirst("Content-Type"))
              .isEqualTo("application/x-protobuf");
          assertThat(exchange.getRequestHeaders().getFirst("tenant")).isEqualTo("demo");
          request.set(ExportProfilesServiceRequest.parseFrom(exchange.getRequestBody()));
          byte[] response = response(partialRejection).toByteArray();
          exchange.sendResponseHeaders(200, response.length == 0 ? -1 : response.length);
          exchange.getResponseBody().write(response);
          exchange.close();
        });
    server.start();
    try (var snapshot = recording()) {
      var exporter =
          new OtlpProfileExporterAdapter(
              new URL(
                  "http://127.0.0.1:" + server.getAddress().getPort() + "/v1development/profiles"),
              "http/protobuf",
              Duration.ofSeconds(15),
              singletonMap("tenant", "demo"),
              Resource.create(Attributes.builder().put("service.name", "checkout").build()));
      exporter.export(snapshot);
      verify(request.get());
      if (partialRejection) {
        logs.assertContains("OTLP Profiles rejected 1 profiles: rejected allocation profile");
      }
    } finally {
      server.stop(0);
    }
  }

  @ParameterizedTest
  @ValueSource(booleans = {false, true})
  void exportsDecodedProfilesOverGrpc(boolean partialRejection) throws Exception {
    AtomicReference<ExportProfilesServiceRequest> request = new AtomicReference<>();
    Server server =
        NettyServerBuilder.forAddress(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0))
            .addService(
                new ProfilesServiceGrpc.ProfilesServiceImplBase() {
                  @Override
                  public void export(
                      ExportProfilesServiceRequest value,
                      StreamObserver<ExportProfilesServiceResponse> observer) {
                    request.set(value);
                    observer.onNext(response(partialRejection));
                    observer.onCompleted();
                  }
                })
            .build()
            .start();
    try (var snapshot = recording()) {
      var exporter =
          new OtlpProfileExporterAdapter(
              new URL("http://127.0.0.1:" + server.getPort()),
              "grpc",
              Duration.ofSeconds(15),
              emptyMap(),
              Resource.create(Attributes.builder().put("service.name", "checkout").build()));
      exporter.export(snapshot);
      verify(request.get());
      if (partialRejection) {
        logs.assertContains("OTLP Profiles rejected 1 profiles: rejected allocation profile");
      }
      var empty =
          JfrOtlpConverter.convert(
              directory.resolve("profile.jfr"),
              snapshot.getEndTime().plusSeconds(1),
              snapshot.getEndTime().plusSeconds(2),
              Resource.empty());
      assertThat(empty.getResourceProfiles(0).getScopeProfiles(0).getProfilesCount()).isZero();
    } finally {
      server.shutdownNow();
    }
  }
}

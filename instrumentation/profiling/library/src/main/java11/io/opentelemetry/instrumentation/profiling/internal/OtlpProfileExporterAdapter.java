/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.instrumentation.profiling.internal;

import io.grpc.ManagedChannel;
import io.grpc.Metadata;
import io.grpc.StatusRuntimeException;
import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder;
import io.grpc.stub.MetadataUtils;
import io.opentelemetry.instrumentation.profiling.ProfileExporterAdapter;
import io.opentelemetry.instrumentation.profiling.ProfileSnapshot;
import io.opentelemetry.proto.collector.profiles.v1development.ExportProfilesServiceRequest;
import io.opentelemetry.proto.collector.profiles.v1development.ExportProfilesServiceResponse;
import io.opentelemetry.proto.collector.profiles.v1development.ProfilesServiceGrpc;
import io.opentelemetry.sdk.resources.Resource;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Duration;
import java.util.Map;
import java.util.logging.Logger;

final class OtlpProfileExporterAdapter implements ProfileExporterAdapter {
  private static final Logger logger = Logger.getLogger(OtlpProfileExporterAdapter.class.getName());
  private final URL endpoint;
  private final String protocol;
  private final int timeoutMillis;
  private final Map<String, String> headers;
  private final Resource resource;

  OtlpProfileExporterAdapter(
      URL endpoint,
      String protocol,
      Duration timeout,
      Map<String, String> headers,
      Resource resource) {
    this.endpoint = endpoint;
    this.protocol = protocol;
    long millis = timeout.toMillis();
    if (millis < 1 || millis > Integer.MAX_VALUE) {
      throw new IllegalArgumentException("Invalid OTLP Profiles timeout");
    }
    this.timeoutMillis = (int) millis;
    this.headers = headers;
    this.resource = resource;
  }

  @Override
  public void export(ProfileSnapshot snapshot) throws IOException {
    try {
      doExport(snapshot);
    } catch (LinkageError failure) {
      throw new IOException("Unable to link OTLP Profiles exporter", failure);
    }
  }

  private void doExport(ProfileSnapshot snapshot) throws IOException {
    Path file = null;
    ExportProfilesServiceRequest request;
    try (InputStream input = snapshot.openStream()) {
      if (input == null) {
        return;
      }
      file = Files.createTempFile("otel-profile-conversion-", ".jfr");
      Files.copy(input, file, StandardCopyOption.REPLACE_EXISTING);
      request =
          JfrOtlpConverter.convert(file, snapshot.getStartTime(), snapshot.getEndTime(), resource);
    } finally {
      if (file != null) {
        Files.deleteIfExists(file);
      }
    }
    if (request.getResourceProfiles(0).getScopeProfiles(0).getProfilesCount() == 0) {
      return;
    }
    if (protocol.equals("grpc")) {
      NettyChannelBuilder builder =
          NettyChannelBuilder.forAddress(
              endpoint.getHost(),
              endpoint.getPort() == -1
                  ? (endpoint.getProtocol().equals("https") ? 443 : 80)
                  : endpoint.getPort());
      if (endpoint.getProtocol().equals("http")) {
        builder.usePlaintext();
      }
      ManagedChannel channel = builder.build();
      try {
        Metadata metadata = new Metadata();
        headers.forEach(
            (key, value) ->
                metadata.put(Metadata.Key.of(key, Metadata.ASCII_STRING_MARSHALLER), value));
        var response =
            ProfilesServiceGrpc.newBlockingStub(channel)
                .withInterceptors(MetadataUtils.newAttachHeadersInterceptor(metadata))
                .withDeadlineAfter(Duration.ofMillis(timeoutMillis))
                .export(request);
        checkResponse(response);
      } catch (StatusRuntimeException exception) {
        throw new IOException("OTLP Profiles gRPC export failed", exception);
      } finally {
        channel.shutdownNow();
      }
      return;
    }
    HttpURLConnection connection = (HttpURLConnection) endpoint.openConnection();
    connection.setInstanceFollowRedirects(false);
    connection.setRequestMethod("POST");
    connection.setDoOutput(true);
    connection.setConnectTimeout(timeoutMillis);
    connection.setReadTimeout(timeoutMillis);
    headers.forEach(connection::setRequestProperty);
    connection.setRequestProperty("Content-Type", "application/x-protobuf");
    connection.setFixedLengthStreamingMode(request.getSerializedSize());
    try {
      try (OutputStream output = connection.getOutputStream()) {
        request.writeTo(output);
      }
      int status = connection.getResponseCode();
      if (status != 200) {
        throw new IOException("OTLP Profiles export failed with HTTP " + status);
      }
      ExportProfilesServiceResponse response;
      try (InputStream input = connection.getInputStream()) {
        response = ExportProfilesServiceResponse.parseFrom(input);
      }
      checkResponse(response);
    } finally {
      connection.disconnect();
    }
  }

  private static void checkResponse(ExportProfilesServiceResponse response) {
    if (response.hasPartialSuccess()) {
      if (response.getPartialSuccess().getRejectedProfiles() > 0) {
        // A successful response with partial rejection must not replay accepted profiles.
        logger.warning(
            "OTLP Profiles rejected "
                + response.getPartialSuccess().getRejectedProfiles()
                + " profiles: "
                + response.getPartialSuccess().getErrorMessage());
      } else if (!response.getPartialSuccess().getErrorMessage().isEmpty()) {
        logger.warning(response.getPartialSuccess().getErrorMessage());
      }
    }
  }
}

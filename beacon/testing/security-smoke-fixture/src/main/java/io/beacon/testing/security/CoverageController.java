/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.beacon.testing.security;

import java.io.ByteArrayInputStream;
import java.io.FileReader;
import java.io.InputStream;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLStreamHandler;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.Certificate;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.Statement;
import java.util.Collections;
import java.util.Map;
import java.util.stream.Stream;
import javax.net.ssl.HttpsURLConnection;
import javax.sql.DataSource;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.request.async.DeferredResult;

/** Local-only fixture operations: HTTPS uses an in-memory handler and never opens a socket. */
@RestController
@RequestMapping("/api/coverage")
class CoverageController {
  private final DataSource dataSource;
  private final Path root;

  CoverageController(DataSource dataSource) throws Exception {
    this.dataSource = dataSource;
    root = Files.createTempDirectory("beacon-coverage-");
    Files.write(root.resolve("sample.txt"), "fixture\n".getBytes(StandardCharsets.UTF_8));
    root.resolve("sample.txt").toFile().deleteOnExit();
    root.toFile().deleteOnExit();
  }

  @GetMapping("/file")
  Map<String, Object> file(@RequestParam String name) throws Exception {
    try (FileReader reader = new FileReader(root.toString() + "/" + name)) {
      return result(reader.read());
    }
  }

  @GetMapping("/lines")
  Map<String, Object> lines(@RequestParam String name) throws Exception {
    try (Stream<String> lines = Files.lines(root.resolve(name))) {
      return result(lines.count());
    }
  }

  @GetMapping("/https")
  Map<String, Object> https(@RequestParam String target) throws Exception {
    URL url =
        new URL(
            null,
            target,
            new URLStreamHandler() {
              @Override
              protected URLConnection openConnection(URL value) {
                return new FixtureHttpsConnection(value);
              }
            });
    // A concrete subclass owner exercises hierarchy matching beyond javax.net.ssl prefixes.
    FixtureHttpsConnection connection = (FixtureHttpsConnection) url.openConnection();
    try (InputStream input = connection.getInputStream()) {
      return result(input.read());
    }
  }

  @GetMapping("/batch")
  Map<String, Object> batch(@RequestParam String value) throws Exception {
    try (Connection connection = dataSource.getConnection();
        Statement statement = connection.createStatement()) {
      statement.addBatch("UPDATE demo_users SET name = name WHERE name = '" + value + "'");
      return result(statement.executeBatch().length);
    }
  }

  @GetMapping("/cleared-batch")
  Map<String, Object> clearedBatch(@RequestParam String value) throws Exception {
    try (Connection connection = dataSource.getConnection();
        Statement statement = connection.createStatement()) {
      statement.addBatch("UPDATE demo_users SET name = name WHERE name = '" + value + "'");
      statement.clearBatch();
      return result(statement.executeBatch().length);
    }
  }

  @GetMapping("/prepared-batch")
  Map<String, Object> preparedBatch(@RequestParam String value) throws Exception {
    try (Connection connection = dataSource.getConnection();
        PreparedStatement statement =
            connection.prepareStatement("UPDATE demo_users SET name = name WHERE name = ?")) {
      statement.setString(1, value);
      statement.addBatch();
      return result(statement.executeBatch().length);
    }
  }

  @GetMapping("/large-update")
  Map<String, Object> largeUpdate(@RequestParam String value) throws Exception {
    try (Connection connection = dataSource.getConnection();
        Statement statement = connection.createStatement()) {
      return result(
          statement.executeLargeUpdate(
              "UPDATE demo_users SET name = name WHERE name = '" + value + "'"));
    }
  }

  @GetMapping("/async-timeout")
  DeferredResult<Map<String, Object>> timeout() {
    return new DeferredResult<>(20L, result("timeout"));
  }

  private static Map<String, Object> result(Object value) {
    return Collections.singletonMap("result", value);
  }

  private static final class FixtureHttpsConnection extends HttpsURLConnection {
    FixtureHttpsConnection(URL url) {
      super(url);
    }

    @Override
    public void connect() {}

    @Override
    public void disconnect() {}

    @Override
    public boolean usingProxy() {
      return false;
    }

    @Override
    public String getCipherSuite() {
      return "fixture";
    }

    @Override
    public Certificate[] getLocalCertificates() {
      return new Certificate[0];
    }

    @Override
    public Certificate[] getServerCertificates() {
      return new Certificate[0];
    }

    @Override
    public InputStream getInputStream() {
      return new ByteArrayInputStream(new byte[] {42});
    }
  }
}

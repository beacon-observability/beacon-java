/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.beacon.testing.jdbc;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@SpringBootApplication
public class JdbcSmokeApplication {
  public static void main(String[] args) {
    SpringApplication.run(JdbcSmokeApplication.class, args);
  }

  @RestController
  static class Queries {
    private static final Logger logger = LoggerFactory.getLogger(Queries.class);
    private final JdbcTemplate jdbc;

    Queries(JdbcTemplate jdbc) {
      this.jdbc = jdbc;
    }

    @GetMapping("/health")
    String health() {
      return "ok";
    }

    @GetMapping("/query")
    String query(@RequestParam("value") String value) {
      logger.info("Executing JDBC smoke query");
      return jdbc.queryForObject("select cast(? as text) as payload", String.class, value);
    }
  }
}

/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.beacon.testing.security;

import java.sql.Connection;
import java.sql.Statement;
import javax.sql.DataSource;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
public class SecuritySmokeApplication {

  public static void main(String[] args) {
    SpringApplication application = new SpringApplication(SecuritySmokeApplication.class);
    application.setWebApplicationType(WebApplicationType.SERVLET);
    application.run(args);
  }

  @Bean
  CommandLineRunner initialize(DataSource dataSource) {
    return args -> {
      try (Connection connection = dataSource.getConnection();
          Statement statement = connection.createStatement()) {
        statement.execute("CREATE TABLE IF NOT EXISTS demo_users (name VARCHAR(128))");
        statement.execute(
            "INSERT INTO demo_users(name) SELECT 'guest' WHERE NOT EXISTS (SELECT 1 FROM demo_users)");
      }
    };
  }
}

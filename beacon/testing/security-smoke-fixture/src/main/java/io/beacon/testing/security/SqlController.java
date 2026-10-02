/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.beacon.testing.security;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.LinkedHashMap;
import java.util.Map;
import javax.sql.DataSource;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/sql")
class SqlController {
  private final DataSource dataSource;

  SqlController(DataSource dataSource) {
    this.dataSource = dataSource;
  }

  @GetMapping
  Map<String, Object> dynamicSql(@RequestParam(defaultValue = "guest") String value)
      throws Exception {
    String sql = "SELECT COUNT(*) FROM demo_users WHERE name = '" + value + "'";
    try (Connection connection = dataSource.getConnection();
        Statement statement = connection.createStatement();
        ResultSet resultSet = statement.executeQuery(sql)) {
      resultSet.next();
      return result("dynamic-sql", sql, resultSet.getInt(1));
    }
  }

  @GetMapping("/parameterized")
  Map<String, Object> parameterizedSql(@RequestParam(defaultValue = "guest") String value)
      throws Exception {
    String sql = "SELECT COUNT(*) FROM demo_users WHERE name = ?";
    try (Connection connection = dataSource.getConnection();
        PreparedStatement statement = connection.prepareStatement(sql)) {
      statement.setString(1, value);
      try (ResultSet resultSet = statement.executeQuery()) {
        resultSet.next();
        return result("parameterized-sql", sql, resultSet.getInt(1));
      }
    }
  }

  @GetMapping("/constant")
  Map<String, Object> constantSql() throws Exception {
    String sql = "SELECT COUNT(*) FROM demo_users";
    try (Connection connection = dataSource.getConnection();
        Statement statement = connection.createStatement();
        ResultSet resultSet = statement.executeQuery(sql)) {
      resultSet.next();
      return result("constant-sql", sql, resultSet.getInt(1));
    }
  }

  private static Map<String, Object> result(String operation, String value, int detail) {
    Map<String, Object> response = new LinkedHashMap<>();
    response.put("operation", operation);
    response.put("value", value);
    response.put("detail", detail);
    return response;
  }
}

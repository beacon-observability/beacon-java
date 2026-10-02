/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.beacon.security.sbom;

import static io.beacon.security.core.Values.map;
import static java.util.Collections.emptyList;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.beacon.security.core.Events;
import io.beacon.security.core.Settings;
import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

final class DependencySnapshot {
  private DependencySnapshot() {}

  // CycloneDX properties and hashes are validated as lists of objects before publication.
  @SuppressWarnings("unchecked")
  static List<Map<String, Object>> events(
      Map<String, Object> event, Iterable<Map<String, Object>> records) throws IOException {
    ObjectMapper json = new ObjectMapper();
    Map<String, Map<String, Object>> unique = new TreeMap<>();
    for (Map<String, Object> record : records) {
      boolean loaded = false;
      for (Map<String, Object> property :
          (List<Map<String, Object>>) record.getOrDefault("properties", emptyList())) {
        loaded |=
            "beacon:security:sbom:loaded".equals(property.get("name"))
                && "true".equals(property.get("value"));
      }
      if (!loaded || !"library".equals(record.get("type"))) {
        continue;
      }
      String group = String.valueOf(record.getOrDefault("group", ""));
      Map<String, Object> row =
          map(
              "name",
              (group.isEmpty() ? "" : group + ":") + record.get("name"),
              "version",
              record.getOrDefault("version", ""));
      if (group.isEmpty() || "".equals(row.get("version"))) {
        for (Map<String, Object> hash :
            (List<Map<String, Object>>) record.getOrDefault("hashes", emptyList())) {
          if ("SHA-256".equals(hash.get("alg"))) {
            row.put("hash", hash.get("content"));
            break;
          }
        }
      }
      unique.put(json.writeValueAsString(row), row);
    }
    Map<String, Object> envelope = Events.record(event);
    envelope.put("event_name", "beacon.security.sbom.snapshot");
    envelope.put("component_count", unique.size());
    envelope.put("part_index", Integer.MAX_VALUE);
    envelope.put("part_count", Integer.MAX_VALUE);
    envelope.put("dependencies", emptyList());
    int maximum =
        Math.min(
            Settings.limit("beacon.security.evidence.max.bytes", 65536),
            Settings.limit("beacon.security.export.sbom.bytes-per-second", 262144));
    int overhead = json.writeValueAsBytes(envelope).length;
    if (overhead > maximum) {
      throw new IOException("dependency_snapshot_envelope_exceeds_budget");
    }
    List<List<Map<String, Object>>> chunks = new ArrayList<>();
    List<Map<String, Object>> chunk = new ArrayList<>();
    chunks.add(chunk);
    int bytes = overhead;
    for (Map<String, Object> row : unique.values()) {
      int size = json.writeValueAsBytes(row).length;
      if (overhead + size > maximum) {
        throw new IOException("dependency_snapshot_item_exceeds_budget");
      }
      if (bytes + size + (chunk.isEmpty() ? 0 : 1) > maximum) {
        chunk = new ArrayList<>();
        chunks.add(chunk);
        bytes = overhead;
      }
      bytes += size + (chunk.isEmpty() ? 0 : 1);
      chunk.add(row);
    }
    List<Map<String, Object>> result = new ArrayList<>();
    for (int index = 0; index < chunks.size(); index++) {
      Map<String, Object> part = new LinkedHashMap<>(envelope);
      part.put("dependencies", chunks.get(index));
      part.put("part_index", index);
      part.put("part_count", chunks.size());
      result.add(part);
    }
    return result;
  }
}

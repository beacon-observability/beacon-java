/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.beacon.security.core;

import static io.beacon.security.core.Values.map;
import static java.util.Arrays.asList;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.util.Map;

/** Projects an exported v2 payload without changing its serialized content. */
public final class SiemEvent {
  public static final String PROFILE = "beacon-security-siem-v1";

  private SiemEvent() {}

  public static byte[] encode(ObjectMapper json, Map<String, Object> event) throws IOException {
    return encode(json, event, json.writeValueAsString(event), Identity.resourceAttributes());
  }

  public static byte[] encode(
      ObjectMapper json, Map<String, Object> event, String message, Map<String, String> resource)
      throws IOException {
    boolean inventory = "beacon.security.sbom.inventory".equals(event.get("event_name"));
    String eventId = text(event, "occurrence_id");
    if (inventory) {
      String index = text(event, "part_index");
      eventId =
          "inventory-"
              + Identity.digest(
                  json.writeValueAsString(
                      asList(
                          text(event, "source"),
                          text(event, "event_name"),
                          text(event, "instance_id"),
                          text(event, "observed_at"),
                          index.isEmpty() ? "0" : index)));
    }
    String tenant = text(resource, "tenant.id");
    return json.writeValueAsBytes(
        map(
            "time",
            text(event, "observed_at"),
            "event_id",
            eventId,
            "event_class",
            inventory ? "software_inventory_info" : "security_finding",
            "source",
            text(event, "source"),
            "service",
            text(resource, "service.name"),
            "tenant_id",
            tenant.trim().isEmpty() ? "default" : tenant,
            "actor",
            "",
            "ip",
            "",
            "action",
            inventory ? "inventory_snapshot" : text(event, "rule"),
            "target",
            text(event, inventory ? "instance_id" : "finding_id"),
            "target_type",
            inventory ? "process" : "finding",
            "outcome",
            inventory ? "success" : "unknown",
            "status",
            "info",
            "severity",
            "informational",
            "message",
            message));
  }

  private static String text(Map<String, ?> values, String key) {
    Object value = values.get(key);
    String text = value == null ? "" : String.valueOf(value);
    return text.trim().isEmpty() ? "" : text;
  }
}

/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.beacon.security.core;

import static io.beacon.security.core.Values.map;

import java.util.Map;

/** Request-specific evidence, independent of vulnerability assessment and finding identity. */
public final class AttackEvidence {
  private final String status;
  private final String reason;

  private AttackEvidence(String status, String reason) {
    this.status = status;
    this.reason = reason;
  }

  public static AttackEvidence unknown(String reason) {
    return new AttackEvidence("unknown", reason);
  }

  public static AttackEvidence none(String reason) {
    return new AttackEvidence("no_evidence", reason);
  }

  public static AttackEvidence suspected(String reason) {
    return new AttackEvidence("suspected", reason);
  }

  public Map<String, Object> fields() {
    return map("status", status, "reason", reason, "outcome", "not_assessed");
  }

  public static String status(Map<String, Object> event) {
    Object evidence = event.get("attack_evidence");
    Object status = evidence instanceof Map ? ((Map<?, ?>) evidence).get("status") : null;
    return "suspected".equals(status)
        ? "suspected"
        : "no_evidence".equals(status) ? "no_evidence" : "unknown";
  }

  public static int rank(Map<String, Object> event) {
    String status = status(event);
    // Preserve uncertainty when several invocations share a request-level occurrence.
    return status.equals("suspected") ? 2 : status.equals("unknown") ? 1 : 0;
  }
}

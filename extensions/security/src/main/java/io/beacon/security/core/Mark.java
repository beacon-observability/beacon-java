/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.beacon.security.core;

import java.util.Map;

public final class Mark {
  public final Node node;
  public final int start;
  public final int end;
  public final boolean exact;

  public Mark(Node node, int start, int end, boolean exact) {
    this.node = node;
    this.start = start;
    this.end = end;
    this.exact = exact;
  }

  public static final class Node {
    public final int id;
    public final Node parent;
    public final Map<String, Object> source;
    public final String operation;
    public final String location;

    public Node(
        int id, Node parent, Map<String, Object> source, String operation, String location) {
      this.id = id;
      this.parent = parent;
      this.source = source;
      this.operation = operation;
      this.location = location;
    }
  }
}

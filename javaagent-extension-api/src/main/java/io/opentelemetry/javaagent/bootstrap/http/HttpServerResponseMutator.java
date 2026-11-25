/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.javaagent.bootstrap.http;

/** Provides the ability to mutate an instrumentation library specific response. */
public interface HttpServerResponseMutator<RESPONSE> {
  void appendHeader(RESPONSE response, String name, String value);

  /**
   * Adds a header only if no case-insensitive match exists at response commit time.
   *
   * <p>The default does nothing. Integrations must opt in on paths that preserve application
   * headers and run before commit.
   */
  default void appendHeaderIfAbsent(RESPONSE response, String name, String value) {}
}

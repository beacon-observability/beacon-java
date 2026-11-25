/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.javaagent.instrumentation.tomcat.common.v7_0;

import io.opentelemetry.javaagent.bootstrap.http.HttpServerResponseMutator;
import org.apache.coyote.Response;

public enum TomcatCommitResponseMutator implements HttpServerResponseMutator<Response> {
  INSTANCE;

  @Override
  public void appendHeader(Response response, String name, String value) {
    response.addHeader(name, value);
  }

  @Override
  public void appendHeaderIfAbsent(Response response, String name, String value) {
    if (!response.containsHeader(name)) {
      response.addHeader(name, value);
    }
  }
}

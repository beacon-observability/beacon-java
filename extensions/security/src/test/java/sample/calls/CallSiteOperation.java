/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package sample.calls;

import java.io.IOException;
import java.io.InputStream;

public interface CallSiteOperation {
  StringBuilder append(StringBuilder target, int value);

  String construct(String input);

  InputStream open(FixtureConnection connection) throws IOException;
}

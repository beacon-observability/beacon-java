/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package sample.calls;

import java.io.IOException;
import java.io.InputStream;

public class CallSiteFixture implements CallSiteOperation {
  @Override
  public StringBuilder append(StringBuilder target, int value) {
    return target.append(value);
  }

  @Override
  public String construct(String input) {
    return new String(input).substring(0, input.length());
  }

  @Override
  public InputStream open(FixtureConnection connection) throws IOException {
    return connection.getInputStream();
  }
}

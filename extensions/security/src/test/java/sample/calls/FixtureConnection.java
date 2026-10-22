/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package sample.calls;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.net.URL;
import java.net.URLConnection;

public class FixtureConnection extends URLConnection {
  public FixtureConnection(URL url) {
    super(url);
  }

  @Override
  public void connect() {}

  @Override
  public InputStream getInputStream() {
    return new ByteArrayInputStream(new byte[] {42});
  }
}

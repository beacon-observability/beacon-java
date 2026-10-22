/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.instrumentation.profiling.internal;

import static java.util.Collections.emptyMap;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

import io.opentelemetry.instrumentation.profiling.ProfileSnapshot;
import java.io.IOException;
import java.net.URL;
import java.nio.file.Path;
import java.time.Duration;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class EmptyProfileExportTest {
  @TempDir Path directory;

  @Test
  void emptyIntervalDoesNotCreateAFile() throws IOException {
    Path output = directory.resolve("profiles");
    new FileProfileExporterAdapter(output).export(mock(ProfileSnapshot.class));
    assertThat(output).doesNotExist();
  }

  @Test
  void emptyIntervalDoesNotOpenAnHttpConnection() throws IOException {
    new DatakitProfileExporterAdapter(
            new URL("http://127.0.0.1:1/profiling"), Duration.ofSeconds(1), emptyMap())
        .export(mock(ProfileSnapshot.class));
  }
}

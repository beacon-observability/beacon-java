/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.instrumentation.profiling.internal;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

import io.opentelemetry.instrumentation.profiling.ProfileSnapshot;
import java.io.IOException;
import java.nio.file.Path;
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
}

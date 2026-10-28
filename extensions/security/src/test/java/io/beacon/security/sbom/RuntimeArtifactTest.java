/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.beacon.security.sbom;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.params.provider.Arguments.argumentSet;

import java.nio.file.Path;
import java.util.stream.Stream;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class RuntimeArtifactTest {
  @ParameterizedTest
  @MethodSource("locations")
  void excludesRuntimeLibrariesWithoutFilteringApplicationCopies(
      String home, String artifact, boolean runtime, @TempDir Path root) {
    assertThat(SbomInventory.runtimeArtifact(root.resolve(artifact), root.resolve(home)))
        .isEqualTo(runtime);
  }

  private static Stream<Arguments> locations() {
    return Stream.of(
        argumentSet("Java 8 extension", "jdk/jre", "jdk/jre/lib/ext/nashorn.jar", true),
        argumentSet("Java 8 runtime", "jdk/jre", "jdk/jre/lib/rt.jar", true),
        argumentSet("Java 8 tools", "jdk/jre", "jdk/lib/tools.jar", true),
        argumentSet("Java 11 library", "jdk", "jdk/lib/jrt-fs.jar", true),
        argumentSet("JDK home layout", "jdk", "jdk/jre/lib/ext/sunec.jar", true),
        argumentSet("Application library", "jdk/jre", "app/lib/nashorn.jar", false),
        argumentSet("Directory prefix", "jdk", "jdk/lib-extra/library.jar", false),
        argumentSet("Other installation", "jdk", "jdk-other/lib/library.jar", false));
  }
}

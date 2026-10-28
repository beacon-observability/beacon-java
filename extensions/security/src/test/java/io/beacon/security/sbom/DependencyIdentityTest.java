/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.beacon.security.sbom;

import static io.beacon.security.core.Values.map;
import static java.util.Arrays.asList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.params.provider.Arguments.argumentSet;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class DependencyIdentityTest {
  @ParameterizedTest
  @MethodSource("vectors")
  void hashesUtf8CompactJsonNameAndVersion(String name, String version, String expected) {
    assertThat(DependencyInventory.identityHash(name, version)).isEqualTo(expected);
  }

  private static Stream<Arguments> vectors() {
    return Stream.of(
        argumentSet(
            "Maven A", "org.example:library-a", "1.0.0", "b783176a5feb4aafd51a712235824a9c"),
        argumentSet(
            "Maven B", "org.example:library-b", "2.0.0", "0359ea1fe3fadfc34c709978103cbb23"),
        argumentSet(
            "Filename identity", "tomcat-embed-core", "9.0.55", "49fd861a05c959cc3707a8c03ce66bf4"),
        argumentSet("UTF-8", "名称:组件", "1.0", "eee75ab173245fe4a3a28c94e1e03ce0"),
        argumentSet("Delimiter in name", "a:b", "c", "940a5f1caf5ab5f70804d0e2c18d16d2"),
        argumentSet("Delimiter in version", "a", "b:c", "b064d2b07324154f9f59ee2b2b9ac418"));
  }

  @Test
  void deduplicatesCoordinatesAcrossPathsAndArtifactContents() throws IOException {
    Component first =
        new Component("library-a", "org.example", "1.0.0", "aabb", "maven-metadata", "/first.jar");
    Component second =
        new Component("library-a", "org.example", "1.0.0", "ccdd", "maven-metadata", "/second.jar");
    first.loaded = true;
    second.loaded = true;

    List<Map<String, Object>> events =
        DependencyInventory.events(
            map("event_name", "beacon.security.sbom.inventory"),
            asList(first.json(), second.json()));

    assertThat(events).hasSize(1);
    assertThat(events.get(0).get("dependencies"))
        .isEqualTo(
            asList(
                map(
                    "name",
                    "org.example:library-a",
                    "version",
                    "1.0.0",
                    "hash",
                    "b783176a5feb4aafd51a712235824a9c")));
    assertThat(DependencyInventory.dependency(first.json()))
        .containsOnlyKeys("name", "version", "hash");
  }
}

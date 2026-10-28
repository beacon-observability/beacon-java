/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.beacon.security.sbom;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Collections.emptyList;
import static java.util.Collections.emptyMap;
import static java.util.Collections.singletonList;
import static java.util.concurrent.TimeUnit.SECONDS;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.beacon.security.core.Events;
import io.beacon.security.core.Identity;
import io.beacon.security.core.Values;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.lang.instrument.Instrumentation;
import java.lang.management.ManagementFactory;
import java.lang.reflect.Proxy;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.FileTime;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.CodeSource;
import java.security.ProtectionDomain;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicReference;
import java.util.jar.JarOutputStream;
import java.util.zip.ZipEntry;
import javax.annotation.Nullable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/** Behavioural acceptance tests for archive discovery and CycloneDX publication. */
class SbomInventoryBehaviorTest {
  private static final String[] SETTINGS = {
    "beacon.security.sbom.output",
    "beacon.security.sbom.refresh.seconds",
    "beacon.security.sbom.max.archive.bytes",
    "beacon.security.sbom.max.scan.bytes",
    "beacon.security.sbom.max.entries",
    "beacon.security.sbom.max.components",
    "beacon.security.sbom.cache.seconds",
    "beacon.security.sbom.build.file",
    "beacon.security.sbom.build.artifact",
    "beacon.security.evidence.max.bytes",
    "beacon.security.local-output.enabled",
    "java.class.path"
  };

  private final Map<String, String> previousSettings = new HashMap<>();
  private final ObjectMapper json = new ObjectMapper();

  @BeforeEach
  void captureSettings() {
    for (String key : SETTINGS) {
      previousSettings.put(key, System.getProperty(key));
    }
    System.setProperty("beacon.security.local-output.enabled", "true");
  }

  @AfterEach
  void restoreSettings() {
    for (String key : SETTINGS) {
      String value = previousSettings.get(key);
      if (value == null) {
        System.clearProperty(key);
      } else {
        System.setProperty(key, value);
      }
    }
  }

  @Test
  void scansOrdinaryJarCoordinatesHashAndLicense(@TempDir Path temp) throws Exception {
    Path artifact =
        mavenJar(temp, "ordinary.jar", "org.example", "ordinary", "1.2.3", "ordinary-payload");
    RecordingReceiver receiver = scan(artifact);

    assertEquals(1, receiver.components.size());
    Component component = receiver.components.get(0).component;
    assertEquals("ordinary", component.name);
    assertEquals("org.example", component.group);
    assertEquals("1.2.3", component.version);
    assertEquals(Component.digest(Files.readAllBytes(artifact)), component.hash);
    assertEquals("maven-metadata", component.source);
    assertTrue(component.licenses.contains("Apache-2.0"));
    assertEquals(artifact.toString(), receiver.components.get(0).location);
    assertTrue(receiver.components.get(0).primary);
    assertTrue(receiver.incomplete.isEmpty());
  }

  @Test
  void scansBootAndWarNestedLibrariesWithContentHashes(@TempDir Path temp) throws Exception {
    byte[] bootDependency = mavenJarBytes("org.boot", "boot-dependency", "2.0.0", "boot");
    Path boot =
        archive(
            temp,
            "application.jar",
            mapOf(
                "BOOT-INF/classes/example.class",
                bytes("class"),
                "BOOT-INF/lib/boot-dependency.jar",
                bootDependency));
    RecordingReceiver bootReceiver = scan(boot);

    Record bootRecord = find(bootReceiver.components, "boot-dependency");
    assertNotNull(bootRecord);
    assertEquals(boot + "!/BOOT-INF/lib/boot-dependency.jar", bootRecord.location);
    assertEquals(Component.digest(bootDependency), bootRecord.component.hash);
    assertTrue(bootRecord.primary);

    byte[] warDependency = mavenJarBytes("org.war", "war-dependency", "3.0.0", "war");
    Path war =
        archive(
            temp,
            "application.war",
            mapOf(
                "WEB-INF/classes/example.class",
                bytes("class"),
                "WEB-INF/lib/war-dependency.jar",
                warDependency));
    RecordingReceiver warReceiver = scan(war);

    Record warRecord = find(warReceiver.components, "war-dependency");
    assertNotNull(warRecord);
    assertEquals(war + "!/WEB-INF/lib/war-dependency.jar", warRecord.location);
    assertEquals(Component.digest(warDependency), warRecord.component.hash);
    assertTrue(warRecord.primary);
  }

  @Test
  void keepsSameCoordinatesWithDifferentContentAsDifferentComponents(@TempDir Path temp)
      throws Exception {
    Path first = mavenJar(temp, "first.jar", "org.example", "same", "1.0.0", "first");
    Path second = mavenJar(temp, "second.jar", "org.example", "same", "1.0.0", "second");

    RecordingReceiver firstReceiver = scan(first);
    RecordingReceiver secondReceiver = scan(second);
    Component firstComponent = firstReceiver.components.get(0).component;
    Component secondComponent = secondReceiver.components.get(0).component;

    assertEquals(firstComponent.purl, secondComponent.purl);
    assertNotEquals(firstComponent.hash, secondComponent.hash);
    assertNotEquals(firstComponent.ref, secondComponent.ref);
  }

  @Test
  void keepsShadedSameCoordinatesDistinctAcrossContainers(@TempDir Path temp) throws Exception {
    byte[] shared = bytes("groupId=org.example\nartifactId=shared\nversion=1.0.0\n");
    byte[] helper = bytes("groupId=org.example\nartifactId=helper\nversion=1.0.0\n");
    Path first =
        archive(
            temp,
            "first-container.jar",
            mapOf(
                "META-INF/maven/org.example/shared/pom.properties", shared,
                "META-INF/maven/org.example/helper/pom.properties", helper));
    Path second =
        archive(
            temp,
            "second-container.jar",
            mapOf(
                "META-INF/maven/org.example/shared/pom.properties", shared,
                "META-INF/maven/org.example/helper/pom.properties", helper));

    Record firstShared = find(scan(first).components, "shared");
    Record secondShared = find(scan(second).components, "shared");
    assertNotNull(firstShared);
    assertNotNull(secondShared);
    assertEquals("shaded-maven-metadata", firstShared.component.source);
    assertEquals("shaded-maven-metadata", secondShared.component.source);
    assertNull(firstShared.component.hash);
    assertNull(secondShared.component.hash);
    assertNotEquals(firstShared.component.ref, secondShared.component.ref);
  }

  @Test
  void reportsMissingMavenIdentityWithoutGuessingVersion(@TempDir Path temp) throws Exception {
    Path artifact = archive(temp, "unidentified.jar", mapOf("payload.class", bytes("class")));
    RecordingReceiver receiver = scan(artifact);

    assertEquals(1, receiver.components.size());
    Component component = receiver.components.get(0).component;
    assertEquals("artifact-file", component.source);
    assertEquals("", component.group);
    assertEquals("", component.version);
    assertEquals("unidentified", component.name);
    assertTrue(receiver.incomplete.contains("missing_maven_identity"));
  }

  @Test
  void mergesByteIdenticalUnknownArtifactsAcrossRenamedLocations(@TempDir Path temp)
      throws Exception {
    Path first = archive(temp, "unknown-first.jar", mapOf("payload.class", bytes("same-bytes")));
    Path renamed =
        archive(temp, "unknown-renamed.jar", mapOf("payload.class", bytes("same-bytes")));
    System.setProperty("java.class.path", first + File.pathSeparator + renamed);
    SbomInventory inventory =
        inventory(temp.resolve("application.cdx.json"), new ArrayList<>(), null);
    try {
      inventory.refresh();
      Map<String, Object> document = read(inventory.output());
      @SuppressWarnings("unchecked")
      List<Map<String, Object>> components =
          (List<Map<String, Object>>) (List<?>) document.get("components");
      assertEquals(1, components.size());
      Map<String, Object> component = components.get(0);
      assertEquals("artifact-file", property(component, "beacon:security:sbom:identity-source"));
      List<?> hashes = (List<?>) component.get("hashes");
      Map<?, ?> hash = (Map<?, ?>) hashes.get(0);
      assertEquals(Component.digest(Files.readAllBytes(first)), hash.get("content"));
      @SuppressWarnings("unchecked")
      List<Map<String, Object>> occurrences =
          (List<Map<String, Object>>)
              (List<?>) ((Map<String, Object>) component.get("evidence")).get("occurrences");
      assertEquals(2, occurrences.size());
      assertTrue(
          occurrences.stream()
              .anyMatch(value -> "unknown-first.jar".equals(value.get("location"))));
      assertTrue(
          occurrences.stream()
              .anyMatch(value -> "unknown-renamed.jar".equals(value.get("location"))));
    } finally {
      inventory.close();
    }
  }

  @Test
  void marksOnlyObservedDynamicArtifactAsLoaded(@TempDir Path temp) throws Exception {
    Path deployed = mavenJar(temp, "deployed.jar", "org.example", "deployed", "1.0.0", "deployed");
    Path dynamic = dynamicJar(temp);
    String originalClasspath = System.getProperty("java.class.path");
    System.setProperty("java.class.path", deployed.toString());

    List<Map<String, Object>> events = new ArrayList<>();
    try (URLClassLoader loader = new URLClassLoader(new URL[] {dynamic.toUri().toURL()}, null)) {
      Class<?> loadedType = Class.forName("sample.dynamic.DynamicFixture", false, loader);
      SbomInventory inventory =
          inventory(temp.resolve("application.cdx.json"), events, instrumentation(loadedType));
      try {
        inventory.refresh();
        Map<String, Object> document = read(inventory.output());
        assertCycloneDx1_7(document);
        Map<String, Object> deployedComponent = component(document, "deployed");
        Map<String, Object> dynamicComponent = component(document, "dynamic-loaded");
        assertNotNull(deployedComponent);
        assertNotNull(dynamicComponent);
        assertEquals("false", property(deployedComponent, "beacon:security:sbom:loaded"));
        assertEquals("true", property(dynamicComponent, "beacon:security:sbom:loaded"));
        assertEquals("true", property(dynamicComponent, "beacon:security:sbom:deployed"));
        Map<String, Object> snapshot =
            event(events, "beacon.security.sbom.inventory", "source", "beacon_security_sbom");
        assertEquals(
            singletonList(dependency("org.dynamic:dynamic-loaded", "9.0.0")),
            snapshot.get("dependencies"));
        Map<String, Object> resolution = inventory.resolve("sample.dynamic.DynamicFixture", loader);
        assertThat(resolution).isEqualTo(dependency("org.dynamic:dynamic-loaded", "9.0.0"));
      } finally {
        inventory.close();
      }
    }
    System.setProperty("java.class.path", originalClasspath);
  }

  @Test
  void resolveDoesNotPairDynamicRefWithAnOlderPublishedRevision(@TempDir Path temp)
      throws Exception {
    Path first = dynamicJar(temp, "dynamic-first.jar", "first");
    Path second = dynamicJar(temp, "dynamic-second.jar", "second");
    CoordinatedLoader firstLoader = new CoordinatedLoader(first, false);
    CoordinatedLoader secondLoader = new CoordinatedLoader(second, false);
    String originalClasspath = System.getProperty("java.class.path");
    AtomicReference<Class<?>[]> loaded = new AtomicReference<>();
    SbomInventory inventory = null;
    try {
      Class<?> firstType = Class.forName("sample.dynamic.DynamicFixture", false, firstLoader);
      loaded.set(new Class<?>[] {firstType});
      System.setProperty("java.class.path", first.toString());
      inventory =
          inventory(
              temp.resolve("application.cdx.json"), new ArrayList<>(), instrumentation(loaded));
      inventory.refresh();
      Map<String, Object> firstResolution =
          inventory.resolve("sample.dynamic.DynamicFixture", firstLoader);
      assertThat(firstResolution).containsEntry("name", "org.dynamic:dynamic-loaded");

      System.setProperty("java.class.path", first + File.pathSeparator + second);
      secondLoader.gate = true;
      SbomInventory activeInventory = inventory;
      AtomicReference<Map<String, Object>> inFlight = new AtomicReference<>();
      Thread resolver =
          new Thread(
              () ->
                  inFlight.set(
                      activeInventory.resolve("sample.dynamic.DynamicFixture", secondLoader)),
              "sbom-resolve-regression");
      resolver.start();
      assertTrue(secondLoader.entered.await(5, SECONDS));

      AtomicReference<Throwable> refreshFailure = new AtomicReference<>();
      Thread publisher =
          new Thread(
              () -> {
                try {
                  activeInventory.refresh();
                } catch (Throwable error) {
                  refreshFailure.set(error);
                }
              },
              "sbom-publish-regression");
      publisher.start();
      publisher.join(10000);
      assertFalse(publisher.isAlive(), "dynamic publication did not complete");
      assertNull(refreshFailure.get());

      secondLoader.release.countDown();
      resolver.join(10000);
      assertFalse(resolver.isAlive(), "resolve did not complete");
      Map<String, Object> inFlightResult = inFlight.get();
      assertNotNull(inFlightResult);
      assertThat(inFlightResult).isEmpty();

      secondLoader.gate = false;
      Map<String, Object> publishedResult =
          inventory.resolve("sample.dynamic.DynamicFixture", secondLoader);
      assertThat(publishedResult).containsEntry("name", "org.dynamic:dynamic-loaded");
    } finally {
      secondLoader.release.countDown();
      if (inventory != null) {
        inventory.close();
      }
      firstLoader.close();
      secondLoader.close();
      System.setProperty("java.class.path", originalClasspath);
    }
  }

  @Test
  void sharedOriginsPreserveAgentExclusionAndLoadedSnapshotChanges(@TempDir Path temp)
      throws Exception {
    Path application = dynamicJar(temp);
    Path agent = mavenJar(temp, "agent.jar", "io.opentelemetry", "javaagent", "1.0", "agent");
    System.setProperty("java.class.path", application + File.pathSeparator + agent);
    byte[] applicationBytes;
    byte[] agentBytes;
    try (InputStream input =
        getClass().getResourceAsStream("/sample/dynamic/DynamicFixture.class")) {
      applicationBytes = readAll(input);
    }
    try (InputStream input =
        getClass().getResourceAsStream("/io/opentelemetry/javaagent/OpenTelemetryAgent.class")) {
      agentBytes = readAll(input);
    }
    URL sharedOrigin = agent.toUri().toURL();
    NestedSourceLoader agentLoader = new NestedSourceLoader();
    Class<?> helper =
        agentLoader.define("sample.dynamic.DynamicFixture", applicationBytes, sharedOrigin);
    Class<?> entry =
        agentLoader.define(
            "io.opentelemetry.javaagent.OpenTelemetryAgent", agentBytes, sharedOrigin);
    Class<?> app =
        new NestedSourceLoader()
            .define("sample.dynamic.DynamicFixture", applicationBytes, application.toUri().toURL());
    AtomicReference<Class<?>[]> loaded =
        new AtomicReference<>(new Class<?>[] {helper, app, helper, entry});
    try (SbomInventory inventory =
        inventory(
            temp.resolve("application.cdx.json"), new ArrayList<>(), instrumentation(loaded))) {
      inventory.refresh();
      Map<String, Object> document = read(inventory.output());
      assertNull(
          component(document, "javaagent"),
          "agent entry may appear after another class sharing its origin");
      assertEquals(
          "true", property(component(document, "dynamic-loaded"), "beacon:security:sbom:loaded"));
      loaded.set(new Class<?>[] {helper, entry});
      inventory.refresh();
      document = read(inventory.output());
      assertNull(component(document, "javaagent"));
      assertEquals(
          "false", property(component(document, "dynamic-loaded"), "beacon:security:sbom:loaded"));
      loaded.set(new Class<?>[] {app, helper, entry});
      inventory.refresh();
      assertEquals(
          "true",
          property(
              component(read(inventory.output()), "dynamic-loaded"),
              "beacon:security:sbom:loaded"));
    }
  }

  @Test
  void keepsBootOuterComponentsWhenApplicationLoadsNestedByteBuddy(@TempDir Path temp)
      throws Exception {
    byte[] byteBuddyJar = mavenJarBytes("net.bytebuddy", "byte-buddy", "1.18.12", "byte-buddy");
    Path outer =
        archive(
            temp,
            "boot-application.jar",
            mapOf(
                "META-INF/maven/example/application/pom.properties",
                    bytes("groupId=example\nartifactId=application\nversion=1.0.0\n"),
                "META-INF/maven/example/application/pom.xml",
                    bytes(
                        "<project><licenses><license><name>Apache-2.0</name></license></licenses></project>"),
                "BOOT-INF/classes/app.marker", bytes("application"),
                "BOOT-INF/lib/byte-buddy.jar", byteBuddyJar));
    String originalClasspath = System.getProperty("java.class.path");
    System.setProperty("java.class.path", outer.toString());
    AtomicReference<Class<?>[]> loaded = new AtomicReference<>();
    try {
      NestedSourceLoader loader = new NestedSourceLoader();
      byte[] applicationBytes;
      try (InputStream input =
          getClass().getResourceAsStream("/sample/dynamic/DynamicFixture.class")) {
        assertNotNull(input, "application fixture class must be available in test output");
        applicationBytes = readAll(input);
      }
      String outerUrl = outer.toUri().toURL().toExternalForm();
      Class<?> applicationType =
          loader.define(
              "sample.dynamic.DynamicFixture",
              applicationBytes,
              new URL(outerUrl + "!/BOOT-INF/classes/"));
      loaded.set(new Class<?>[] {applicationType});
      SbomInventory inventory =
          inventory(
              temp.resolve("application.cdx.json"), new ArrayList<>(), instrumentation(loaded));
      try {
        inventory.refresh();
        Map<String, Object> initial = read(inventory.output());
        assertNotNull(component(initial, "application"));
        assertNotNull(component(initial, "byte-buddy"));
        assertEquals(
            "example:application",
            inventory.resolve("sample.dynamic.DynamicFixture", loader).get("name"));

        byte[] byteBuddyBytes;
        try (InputStream input =
            getClass().getResourceAsStream("/net/bytebuddy/TestByteBuddy.class")) {
          assertNotNull(input, "Byte Buddy namespace fixture must be available in test output");
          byteBuddyBytes = readAll(input);
        }
        Class<?> byteBuddyType =
            loader.define(
                "net.bytebuddy.TestByteBuddy",
                byteBuddyBytes,
                new URL(outerUrl + "!/BOOT-INF/lib/byte-buddy.jar/"));
        loaded.set(new Class<?>[] {applicationType, byteBuddyType});
        inventory.refresh();
        Map<String, Object> after = read(inventory.output());
        assertNotNull(
            component(after, "application"),
            "nested Byte Buddy must not suppress the Boot outer root");
        assertNotNull(
            component(after, "byte-buddy"),
            "business Byte Buddy dependency must remain in the inventory");
        assertEquals(
            "example:application",
            inventory.resolve("sample.dynamic.DynamicFixture", loader).get("name"));
      } finally {
        inventory.close();
      }
    } finally {
      restore("java.class.path", originalClasspath);
    }
  }

  @Test
  void identifiesRuntimeWithoutExportingApplicationId(@TempDir Path temp) throws Exception {
    Path artifact =
        mavenJar(temp, "identity.jar", "org.example", "identity", "1.0.0", "same-release");
    String originalClasspath = System.getProperty("java.class.path");
    System.setProperty("java.class.path", artifact.toString());
    Map<String, String> identity = new HashMap<>();
    identity.put("service.namespace", "test");
    identity.put("service.name", "identity");
    List<Map<String, Object>> events = new ArrayList<>();
    System.setProperty(
        "beacon.security.sbom.output", temp.resolve("first/application.cdx.json").toString());
    SbomInventory first = new SbomInventory(instrumentation(), events::add, identity);
    System.setProperty(
        "beacon.security.sbom.output", temp.resolve("second/application.cdx.json").toString());
    SbomInventory second = new SbomInventory(null, ignored -> {}, identity);
    try {
      first.refresh();
      second.refresh();
      Map<String, Object> firstDocument = read(first.output());
      Map<String, Object> secondDocument = read(second.output());

      assertThat(documentProperty(firstDocument, "beacon:security:application-id")).isNull();
      assertThat(documentProperty(secondDocument, "beacon:security:application-id")).isNull();
      assertThat(documentProperty(firstDocument, "beacon:security:process-instance-id"))
          .isEqualTo(Identity.INSTANCE);
      assertThat(documentProperty(secondDocument, "beacon:security:process-instance-id"))
          .isEqualTo(Identity.INSTANCE);
      assertThat(firstDocument.get("serialNumber")).isEqualTo("urn:uuid:" + Identity.INSTANCE);
      assertThat(applicationComponentRef(firstDocument)).isEqualTo(Identity.INSTANCE);
      assertThat(applicationComponentRef(secondDocument)).isEqualTo(Identity.INSTANCE);
      assertThat(events).isNotEmpty();
      for (Map<String, Object> event : events) {
        assertThat(event)
            .containsEntry("instance_id", Identity.INSTANCE)
            .containsEntry("schema_version", 2)
            .doesNotContainKey("application_id");
      }
      assertThat(first.resolve("missing.Type", getClass().getClassLoader())).isEmpty();
      assertThat(Files.exists(first.output().resolveSibling("sbom-history.json"))).isFalse();
    } finally {
      first.close();
      second.close();
      restore("java.class.path", originalClasspath);
    }
  }

  @Test
  void rebuildsCurrentInventoryAfterSamePathReplacement(@TempDir Path temp) throws Exception {
    Path firstArtifact =
        mavenJar(temp, "first.jar", "org.example", "first-release", "1.0.0", "first-content");
    Path secondArtifact =
        mavenJar(
            temp,
            "second.jar",
            "org.example",
            "second-release",
            "2.0.0",
            "second-content-that-is-longer");
    Path deployed = temp.resolve("application.jar");
    Files.copy(firstArtifact, deployed);
    String originalClasspath = System.getProperty("java.class.path");
    System.setProperty("java.class.path", deployed.toString());
    List<Map<String, Object>> events = new ArrayList<>();
    SbomInventory inventory = inventory(temp.resolve("application.cdx.json"), events, null);
    try {
      inventory.refresh();
      Map<String, Object> firstDocument = read(inventory.output());
      String firstRef = stringValue(component(firstDocument, "first-release").get("bom-ref"));

      Files.copy(secondArtifact, deployed, StandardCopyOption.REPLACE_EXISTING);
      Files.setLastModifiedTime(deployed, FileTime.fromMillis(System.currentTimeMillis() + 2000));
      inventory.refresh();
      Map<String, Object> secondDocument = read(inventory.output());

      assertNull(component(secondDocument, "first-release"));
      Map<String, Object> current = component(secondDocument, "second-release");
      assertNotNull(current);
      assertNotEquals(firstRef, current.get("bom-ref"));

    } finally {
      inventory.close();
      restore("java.class.path", originalClasspath);
    }
  }

  @Test
  void retriesAnUnreadableArtifactWhenItBecomesReadable(@TempDir Path temp) throws Exception {
    Path missing = temp.resolve("appears-later.jar");
    Path artifact = mavenJar(temp, "ready.jar", "org.example", "retryable", "1.0.0", "ready");
    String originalClasspath = System.getProperty("java.class.path");
    System.setProperty("java.class.path", missing.toString());
    SbomInventory inventory =
        inventory(temp.resolve("application.cdx.json"), new ArrayList<>(), null);
    try {
      inventory.refresh();
      Map<String, Object> incomplete = read(inventory.output());
      assertTrue(completenessReasons(incomplete).contains("unreadable_artifact"));
      assertTrue(((List<?>) incomplete.get("components")).isEmpty());

      Files.copy(artifact, missing);
      inventory.refresh();
      Map<String, Object> recovered = read(inventory.output());
      assertNotNull(component(recovered, "retryable"));
      assertFalse(completenessReasons(recovered).contains("unreadable_artifact"));
    } finally {
      inventory.close();
      restore("java.class.path", originalClasspath);
    }
  }

  @Test
  void publishesAnEmptyListAfterArtifactDeletion(@TempDir Path temp) throws Exception {
    Path artifact = mavenJar(temp, "removed.jar", "org.example", "removed", "1.0.0", "to-remove");
    String originalClasspath = System.getProperty("java.class.path");
    System.setProperty("java.class.path", artifact.toString());
    List<Map<String, Object>> events = new ArrayList<>();
    SbomInventory inventory = inventory(temp.resolve("application.cdx.json"), events, null);
    try {
      inventory.refresh();
      System.setProperty("java.class.path", "");
      inventory.refresh();
      Map<String, Object> current = read(inventory.output());
      assertTrue(((List<?>) current.get("components")).isEmpty());
      Map<String, Object> snapshot =
          event(events, "beacon.security.sbom.inventory", "source", "beacon_security_sbom");
      assertNotNull(snapshot);
      assertTrue(((List<?>) snapshot.get("dependencies")).isEmpty());

      assertThat(Files.exists(inventory.output().resolveSibling("sbom-history.json"))).isFalse();
      assertThat(inventory.health()).containsEntry("status", "ok");
    } finally {
      inventory.close();
      restore("java.class.path", originalClasspath);
    }
  }

  @Test
  void mergesExternalBuildSbomMetadataAndReportsQuality(@TempDir Path temp) throws Exception {
    Path artifact =
        archive(
            temp,
            "runtime.jar",
            mapOf(
                "META-INF/maven/org.build/runtime/pom.properties",
                bytes("groupId=org.build\nartifactId=runtime\nversion=4.0.0\n"),
                "payload.class",
                bytes("class")));
    Map<String, Object> build = new LinkedHashMap<>();
    build.put("bomFormat", "CycloneDX");
    build.put("specVersion", "1.7");
    build.put("serialNumber", "urn:uuid:build-sbom");
    build.put(
        "metadata",
        mapOfObjects("component", mapOfObjects("type", "application", "bom-ref", "build-app")));
    build.put(
        "components",
        singletonList(
            mapOfObjects(
                "type",
                "library",
                "bom-ref",
                "runtime-ref",
                "group",
                "org.build",
                "name",
                "runtime",
                "version",
                "4.0.0",
                "purl",
                "pkg:maven/org.build/runtime@4.0.0",
                "licenses",
                singletonList(mapOfObjects("license", mapOfObjects("id", "MIT"))))));
    build.put(
        "dependencies",
        singletonList(mapOfObjects("ref", "build-app", "dependsOn", singletonList("runtime-ref"))));
    Path buildFile = temp.resolve("application-build.cdx.json");
    Files.write(buildFile, json.writeValueAsBytes(build));
    String originalClasspath = System.getProperty("java.class.path");
    System.setProperty("java.class.path", artifact.toString());
    System.setProperty("beacon.security.sbom.build.file", buildFile.toString());
    System.setProperty("beacon.security.sbom.build.artifact", "build-output");
    SbomInventory inventory =
        inventory(temp.resolve("application.cdx.json"), new ArrayList<>(), null);
    try {
      inventory.refresh();
      Map<String, Object> document = read(inventory.output());
      assertCycloneDx1_7(document);
      Map<String, Object> runtime = component(document, "runtime");
      assertNotNull(runtime);
      assertEquals("pkg:maven/org.build/runtime@4.0.0", runtime.get("purl"));
      assertEquals("MIT", licenseName(runtime));
      assertEquals(
          "build-sbom-declaration", property(runtime, "beacon:security:sbom:license-source"));
      assertEquals("1", quality(document).get("with_license").toString());
      assertTrue(
          containsDependency(
              (List<?>) document.get("dependencies"),
              applicationComponentRef(document),
              stringValue(runtime.get("bom-ref"))));
    } finally {
      inventory.close();
      restore("java.class.path", originalClasspath);
    }
  }

  @Test
  void importsEmbeddedCycloneDxComponentsAndDependencyEdges(@TempDir Path temp) throws Exception {
    Map<String, Object> declared = new LinkedHashMap<>();
    declared.put("bomFormat", "CycloneDX");
    declared.put("specVersion", "1.7");
    declared.put("serialNumber", "urn:uuid:declared");
    declared.put(
        "metadata",
        mapOfObjects("component", mapOfObjects("type", "application", "bom-ref", "app")));
    declared.put(
        "components",
        singletonList(
            mapOfObjects(
                "type",
                "library",
                "bom-ref",
                "dep-ref",
                "group",
                "org.build",
                "name",
                "declared-dependency",
                "version",
                "5.0.0",
                "purl",
                "pkg:maven/org.build/declared-dependency@5.0.0")));
    declared.put(
        "dependencies",
        singletonList(mapOfObjects("ref", "app", "dependsOn", singletonList("dep-ref"))));
    byte[] embedded = json.writeValueAsBytes(declared);
    Path artifact =
        archive(temp, "with-build-sbom.jar", mapOf("META-INF/sbom/build.cdx.json", embedded));
    List<Map<String, Object>> events = new ArrayList<>();
    System.setProperty("java.class.path", artifact.toString());
    SbomInventory inventory = inventory(temp.resolve("application.cdx.json"), events, null);
    try {
      inventory.refresh();
      Map<String, Object> document = read(inventory.output());
      assertCycloneDx1_7(document);
      Map<String, Object> importedComponent = component(document, "declared-dependency");
      assertNotNull(importedComponent);
      assertEquals("pkg:maven/org.build/declared-dependency@5.0.0", importedComponent.get("purl"));
      Map<String, Object> outerComponent = component(document, "with-build-sbom");
      assertNotNull(outerComponent);
      List<?> dependencies = (List<?>) document.get("dependencies");
      assertTrue(
          containsDependency(
              dependencies,
              stringValue(outerComponent.get("bom-ref")),
              stringValue(importedComponent.get("bom-ref"))));
    } finally {
      inventory.close();
    }
  }

  @Test
  void omitsUnresolvedDependencyEdgesInsteadOfPublishingEmptyLeaf(@TempDir Path temp)
      throws Exception {
    Map<String, Object> declared = new LinkedHashMap<>();
    declared.put("bomFormat", "CycloneDX");
    declared.put("specVersion", "1.7");
    declared.put("serialNumber", "urn:uuid:declared-unresolved");
    declared.put(
        "metadata",
        mapOfObjects("component", mapOfObjects("type", "application", "bom-ref", "app")));
    declared.put(
        "dependencies",
        singletonList(mapOfObjects("ref", "app", "dependsOn", singletonList("missing-ref"))));
    Path artifact =
        archive(
            temp,
            "with-unresolved-build-sbom.jar",
            mapOf("META-INF/sbom/build.cdx.json", json.writeValueAsBytes(declared)));
    System.setProperty("java.class.path", artifact.toString());
    SbomInventory inventory =
        inventory(temp.resolve("application.cdx.json"), new ArrayList<>(), null);
    try {
      inventory.refresh();
      Map<String, Object> document = read(inventory.output());
      List<?> dependencies = (List<?>) document.get("dependencies");
      for (Object value : dependencies) {
        if (!(value instanceof Map)) {
          continue;
        }
        Map<?, ?> dependency = (Map<?, ?>) value;
        assertFalse(((List<?>) dependency.get("dependsOn")).isEmpty());
      }
      assertTrue(completenessReasons(document).contains("unresolved_declared_dependency"));
    } finally {
      inventory.close();
    }
  }

  @Test
  void publishesEveryCollectionEvenWhenUnchanged(@TempDir Path temp) throws Exception {
    Path artifact = mavenJar(temp, "stable.jar", "org.example", "stable", "1.0.0", "stable");
    System.setProperty("java.class.path", artifact.toString());
    List<Map<String, Object>> events = new ArrayList<>();
    SbomInventory inventory = inventory(temp.resolve("application.cdx.json"), events, null);
    try {
      inventory.refresh();
      inventory.refresh();
      assertThat(events).hasSize(2);
      assertThat(events.get(1).get("dependencies")).isEqualTo(events.get(0).get("dependencies"));
      assertThat(events.get(1).get("observed_at")).isNotEqualTo(events.get(0).get("observed_at"));
      assertThat(events.get(1))
          .doesNotContainKeys("revision", "sbom_id", "release_id", "service", "runtime");
    } finally {
      inventory.close();
    }
  }

  @Test
  void retainsPreviousSnapshotAndRetriesAfterEnvelopeBudgetFailure(@TempDir Path temp)
      throws Exception {
    Path first = mavenJar(temp, "first.jar", "org.example", "first", "1.0.0", "first");
    Path second = mavenJar(temp, "second.jar", "org.example", "second", "1.0.0", "second");
    System.setProperty("java.class.path", first.toString());
    List<Map<String, Object>> events = new ArrayList<>();
    SbomInventory inventory = inventory(temp.resolve("application.cdx.json"), events, null);
    String previousLimit = System.getProperty("beacon.security.evidence.max.bytes");
    try {
      inventory.refresh();
      byte[] previous = Files.readAllBytes(inventory.output());
      System.setProperty("java.class.path", first + File.pathSeparator + second);
      System.setProperty("beacon.security.evidence.max.bytes", "1");
      assertThrows(IOException.class, inventory::refresh);
      assertTrue(Arrays.equals(previous, Files.readAllBytes(inventory.output())));
      System.setProperty("beacon.security.evidence.max.bytes", "65536");
      inventory.refresh();
      assertNotNull(component(read(inventory.output()), "second"));
      assertNotNull(
          event(events, "beacon.security.sbom.inventory", "source", "beacon_security_sbom"));
    } finally {
      if (previousLimit == null) {
        System.clearProperty("beacon.security.evidence.max.bytes");
      } else {
        System.setProperty("beacon.security.evidence.max.bytes", previousLimit);
      }
      inventory.close();
    }
  }

  @Test
  void localWriteFailureDoesNotBlockInventoryDelivery(@TempDir Path temp) throws Exception {
    Path firstArtifact = mavenJar(temp, "first.jar", "org.example", "first", "1.0.0", "first");
    Path secondArtifact = mavenJar(temp, "second.jar", "org.example", "second", "1.0.0", "second");
    Path output = temp.resolve("nested-output/application.cdx.json");
    System.setProperty("java.class.path", firstArtifact.toString());
    List<Map<String, Object>> events = new ArrayList<>();
    SbomInventory inventory = inventory(output, events, null);
    Set<PosixFilePermission> writable = PosixFilePermissions.fromString("rwx------");
    Set<PosixFilePermission> readOnly = PosixFilePermissions.fromString("r-x------");
    try {
      inventory.refresh();
      byte[] previous = Files.readAllBytes(output);
      Path parent = output.getParent();
      try {
        Files.setPosixFilePermissions(parent, readOnly);
      } catch (UnsupportedOperationException error) {
        return;
      }
      assumeTrue(
          !Files.isWritable(parent), "write-failure test requires a non-root POSIX test process");
      System.setProperty("java.class.path", firstArtifact + File.pathSeparator + secondArtifact);
      inventory.refresh();
      assertTrue(Arrays.equals(previous, Files.readAllBytes(output)));
      assertThat(events).hasSize(2);
    } finally {
      try {
        Files.setPosixFilePermissions(output.getParent(), writable);
      } catch (UnsupportedOperationException ignored) {
        // The earlier capability check skips this test on filesystems without POSIX permissions.
      }
      inventory.close();
    }
  }

  @Test
  void reportsZipReadLimitInsteadOfReadingUnboundedEntry(@TempDir Path temp) throws Exception {
    String previousLimit = System.getProperty("beacon.security.sbom.max.archive.bytes");
    System.setProperty("beacon.security.sbom.max.archive.bytes", "64");
    try {
      byte[] oversized = new byte[2048];
      for (int i = 0; i < oversized.length; i++) {
        oversized[i] = (byte) (i * 31);
      }
      Path artifact =
          archive(temp, "oversized.jar", mapOf("BOOT-INF/lib/oversized.jar", oversized));
      RecordingReceiver receiver = scan(artifact);
      assertTrue(receiver.incomplete.contains("archive_byte_limit"));
    } finally {
      if (previousLimit == null) {
        System.clearProperty("beacon.security.sbom.max.archive.bytes");
      } else {
        System.setProperty("beacon.security.sbom.max.archive.bytes", previousLimit);
      }
    }
  }

  @Test
  void skipsLargeUninterestingEntriesWithoutInflating(@TempDir Path temp) throws IOException {
    System.setProperty("beacon.security.sbom.max.archive.bytes", "64");
    Path artifact =
        archive(
            temp,
            "large-resource.jar",
            mapOf(
                "payload.bin",
                new byte[2 * 1024 * 1024],
                "META-INF/maven/org.example/library/pom.properties",
                bytes("groupId=org.example\nartifactId=library\nversion=1.0\n")));
    System.setProperty(
        "beacon.security.sbom.max.scan.bytes", Long.toString(Files.size(artifact) + 128));

    RecordingReceiver receiver = scan(artifact);

    assertThat(receiver.incomplete).isEmpty();
    assertThat(receiver.components).hasSize(1);
    assertThat(receiver.components.get(0).component.name).isEqualTo("library");
    assertThat(receiver.components.get(0).component.hash)
        .isEqualTo(Component.digest(Files.readAllBytes(artifact)));
  }

  @Test
  void skipsLargeResourcesInsideNestedLibraries(@TempDir Path temp) throws IOException {
    Path dependency =
        archive(
            temp,
            "dependency.jar",
            mapOf(
                "payload.bin",
                new byte[2 * 1024 * 1024],
                "META-INF/maven/org.example/library/pom.properties",
                bytes("groupId=org.example\nartifactId=library\nversion=1.0\n")));
    byte[] nested = Files.readAllBytes(dependency);
    Path artifact =
        archive(
            temp,
            "application.jar",
            mapOf(
                "BOOT-INF/lib/dependency.jar",
                nested,
                "META-INF/maven/org.example/application/pom.properties",
                bytes("groupId=org.example\nartifactId=application\nversion=1.0\n")));
    System.setProperty("beacon.security.sbom.max.archive.bytes", Integer.toString(nested.length));
    System.setProperty(
        "beacon.security.sbom.max.scan.bytes",
        Long.toString(Files.size(artifact) + nested.length + 128));

    RecordingReceiver receiver = scan(artifact);

    assertThat(receiver.incomplete).isEmpty();
    assertThat(receiver.components).hasSize(2);
    Record library = find(receiver.components, "library");
    assertThat(library).isNotNull();
    assertThat(library.location).isEqualTo(artifact + "!/BOOT-INF/lib/dependency.jar");
    assertThat(library.component.hash).isEqualTo(Component.digest(nested));
  }

  @Test
  void reportsTotalReadBudgetSeparatelyFromArchiveSize(@TempDir Path temp) throws IOException {
    Path artifact = mavenJar(temp, "library.jar", "org.example", "library", "1.0", "payload");
    System.setProperty(
        "beacon.security.sbom.max.scan.bytes", Long.toString(Files.size(artifact) + 8));

    RecordingReceiver receiver = scan(artifact);

    assertThat(receiver.incomplete).containsExactly("scan_byte_limit");
    assertThat(receiver.components).isEmpty();
  }

  @Test
  void stopsBeforeOpeningArchiveWhenHashExceedsBudget(@TempDir Path temp) throws IOException {
    Path artifact = mavenJar(temp, "library.jar", "org.example", "library", "1.0", "payload");
    System.setProperty(
        "beacon.security.sbom.max.scan.bytes", Long.toString(Files.size(artifact) - 1));

    RecordingReceiver receiver = scan(artifact);

    assertThat(receiver.incomplete).containsExactly("scan_byte_limit");
    assertThat(receiver.components).isEmpty();
  }

  @Test
  void boundsMetadataReadsSeparatelyFromArchiveSize(@TempDir Path temp) throws IOException {
    Path artifact =
        archive(
            temp,
            "large-metadata.jar",
            mapOf("META-INF/maven/org.example/library/pom.properties", new byte[256 * 1024 + 1]));

    RecordingReceiver receiver = scan(artifact);

    assertThat(receiver.incomplete).containsExactly("metadata_byte_limit");
    assertThat(receiver.components).isEmpty();
  }

  @Test
  void checksActualNestedBytesEvenWhenDirectoryUnderstatesSize(@TempDir Path temp)
      throws IOException {
    byte[] nested = mavenJarBytes("org.example", "library", "1.0", "payload");
    Path artifact = archive(temp, "misleading-size.jar", mapOf("BOOT-INF/lib/library.jar", nested));
    // Understate only the central directory's uncompressed size, leaving the data intact.
    zeroCentralDirectoryField(artifact, 24);
    System.setProperty("beacon.security.sbom.max.archive.bytes", "64");

    RecordingReceiver receiver = scan(artifact);

    assertThat(receiver.incomplete).containsExactly("archive_byte_limit");
    assertThat(receiver.components).isEmpty();
  }

  @ParameterizedTest
  @ValueSource(
      strings = {"META-INF/maven/org.example/library/pom.properties", "BOOT-INF/lib/library.jar"})
  void rejectsCorruptSelectedEntry(String entryName, @TempDir Path temp) throws IOException {
    byte[] payload =
        entryName.endsWith(".jar")
            ? mavenJarBytes("org.example", "library", "1.0", "payload")
            : bytes("groupId=org.example\nartifactId=library\nversion=1.0\n");
    Path artifact = archive(temp, "corrupt.jar", mapOf(entryName, payload));
    zeroCentralDirectoryField(artifact, 16);

    RecordingReceiver receiver = scan(artifact);

    assertThat(receiver.incomplete).containsExactly("artifact_scan_ZipException");
    assertThat(receiver.components).isEmpty();
  }

  @Test
  void countsSkippedDirectoryEntriesAcrossNestedArchives(@TempDir Path temp) throws IOException {
    byte[] nested = mavenJarBytes("org.example", "library", "1.0", "payload");
    Path artifact =
        archive(
            temp,
            "entry-limit.jar",
            mapOf("BOOT-INF/lib/library.jar", nested, "payload.bin", bytes("uninteresting")));
    System.setProperty("beacon.security.sbom.max.entries", "4");

    RecordingReceiver receiver = scan(artifact);

    assertThat(receiver.incomplete).contains("archive_entry_limit");
    assertThat(find(receiver.components, "library")).isNotNull();
  }

  @ParameterizedTest
  @ValueSource(booleans = {true, false})
  void limitsNestedArchiveDepth(boolean diagnostic, @TempDir Path temp) throws IOException {
    Path artifact = mavenJar(temp, "leaf.jar", "org.example", "too-deep", "1.0", "payload");
    String nestedPath = "";
    for (int i = 0; i < 5; i++) {
      byte[] nested = Files.readAllBytes(artifact);
      artifact = archive(temp, "level-" + i + ".jar", mapOf("BOOT-INF/lib/inner.jar", nested));
      nestedPath += "!/BOOT-INF/lib/inner.jar";
    }
    System.setProperty("beacon.security.local-output.enabled", Boolean.toString(diagnostic));

    RecordingReceiver receiver = new RecordingReceiver();
    new ArchiveScanner(receiver).scan(artifact, artifact + (diagnostic ? "" : nestedPath));

    assertThat(receiver.incomplete).contains("archive_depth_limit");
    assertThat(find(receiver.components, "too-deep")).isNull();
  }

  @Test
  void retainsPublishedInventoryWhenNewArchiveExceedsBudget(@TempDir Path temp) throws Exception {
    Path first = dynamicJar(temp);
    Path oversized =
        archive(temp, "oversized.jar", mapOf("BOOT-INF/lib/large.jar", new byte[4096]));
    System.setProperty("beacon.security.local-output.enabled", "false");
    System.setProperty("beacon.security.sbom.max.archive.bytes", "1024");
    System.setProperty("java.class.path", first.toString());
    try (URLClassLoader loader = new URLClassLoader(new URL[] {first.toUri().toURL()}, null)) {
      Class<?> loaded = loader.loadClass("sample.dynamic.DynamicFixture");
      AtomicReference<Class<?>[]> observed = new AtomicReference<>(new Class<?>[] {loaded});
      List<Map<String, Object>> events = new ArrayList<>();
      try (SbomInventory inventory = new SbomInventory(instrumentation(observed), events::add)) {
        inventory.refresh();
        Map<String, Object> previous = inventory.resolve(loaded.getName(), loader);
        assertThat(previous).isNotEmpty();
        assertThat(events).hasSize(1);

        System.setProperty("java.class.path", first + File.pathSeparator + oversized);
        observed.set(
            new Class<?>[] {
              loaded, typeAt(new URL(oversized.toUri().toURL() + "!/BOOT-INF/lib/large.jar"))
            });
        inventory.refresh();

        assertThat(events).hasSize(1);
        assertThat(inventory.resolve(loaded.getName(), loader)).isEqualTo(previous);
        assertThat(inventory.health())
            .containsEntry("status", "error")
            .containsEntry("last_error_type", "archive_byte_limit");
      }
    }
  }

  @Test
  void productionReadsMetadataWithoutHashingTheWholeArchive(@TempDir Path temp) throws IOException {
    Path artifact = mavenJar(temp, "library.jar", "org.example", "library", "1.0", "payload");
    System.setProperty("beacon.security.local-output.enabled", "false");
    System.setProperty("beacon.security.sbom.max.scan.bytes", "128");
    assertThat(Files.size(artifact)).isGreaterThan(128);

    RecordingReceiver receiver = scan(artifact);

    assertThat(receiver.incomplete).isEmpty();
    assertThat(receiver.components).hasSize(1);
    Component component = receiver.components.get(0).component;
    assertThat(component.name).isEqualTo("library");
    assertThat(component.hash).isNull();
  }

  @Test
  void productionKeepsDistinctOriginsWithTheSameCoordinates(@TempDir Path temp) throws IOException {
    Path first = mavenJar(temp, "first.jar", "org.example", "library", "1.0", "first");
    Path second = mavenJar(temp, "second.jar", "org.example", "library", "1.0", "second");
    System.setProperty("beacon.security.local-output.enabled", "false");

    Component firstComponent = scan(first).components.get(0).component;
    Component secondComponent = scan(second).components.get(0).component;

    assertThat(firstComponent.hash).isNull();
    assertThat(secondComponent.hash).isNull();
    assertThat(firstComponent.purl).isEqualTo(secondComponent.purl);
    assertThat(firstComponent.ref).isNotEqualTo(secondComponent.ref);
  }

  @Test
  void productionIdentifiesIncompleteCoordinatesWithoutHashingArtifactContents(@TempDir Path temp)
      throws IOException {
    Path artifact =
        archive(
            temp,
            "unknown.jar",
            mapOf(
                "META-INF/maven/org.example/library/pom.properties",
                bytes("artifactId=library\nversion=1.0\n")));
    System.setProperty("beacon.security.local-output.enabled", "false");

    RecordingReceiver receiver = scan(artifact);

    assertThat(receiver.incomplete).isEmpty();
    assertThat(receiver.components.get(0).component.hash).isNull();
    assertThat(DependencyInventory.dependency(receiver.components.get(0).component.json()))
        .isEqualTo(dependency("library", "1.0"));
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "BOOT-INF/lib/library.jar",
        "WEB-INF/lib/library.jar",
        "WEB-INF/lib-provided/library.jar"
      })
  void productionScansOnlyTheSelectedNestedArchive(String entry, @TempDir Path temp)
      throws IOException {
    byte[] dependency = mavenJarBytes("org.example", "library", "1.0", "payload");
    Path artifact =
        archive(
            temp,
            "application.jar",
            mapOf(
                "BOOT-INF/lib/unloaded.jar",
                new byte[8192],
                "large-resource.bin",
                new byte[2 * 1024 * 1024],
                entry,
                dependency));
    System.setProperty("beacon.security.local-output.enabled", "false");
    System.setProperty("beacon.security.sbom.max.archive.bytes", "1024");
    System.setProperty(
        "beacon.security.sbom.max.scan.bytes", Integer.toString(dependency.length + 128));
    RecordingReceiver receiver = new RecordingReceiver();

    new ArchiveScanner(receiver).scan(artifact, artifact + "!/" + entry);

    assertThat(receiver.incomplete).isEmpty();
    assertThat(receiver.components).hasSize(1);
    assertThat(receiver.components.get(0).component.name).isEqualTo("library");
    assertThat(receiver.components.get(0).component.hash).isNull();
    assertThat(receiver.components.get(0).location).isEqualTo(artifact + "!/" + entry);
  }

  @Test
  void productionFollowsMultipleNestedEntriesToTheLoadedLibrary(@TempDir Path temp)
      throws IOException {
    byte[] library = mavenJarBytes("org.example", "library", "1.0", "payload");
    Path middle = archive(temp, "middle.jar", mapOf("BOOT-INF/lib/library.jar", library));
    Path artifact =
        archive(
            temp, "application.jar", mapOf("BOOT-INF/lib/middle.jar", Files.readAllBytes(middle)));
    String target = artifact + "!/BOOT-INF/lib/middle.jar!/BOOT-INF/lib/library.jar";
    System.setProperty("beacon.security.local-output.enabled", "false");
    System.setProperty(
        "beacon.security.sbom.max.scan.bytes",
        Long.toString(Files.size(middle) + library.length + 128));
    RecordingReceiver receiver = new RecordingReceiver();

    new ArchiveScanner(receiver).scan(artifact, target);

    assertThat(receiver.incomplete).isEmpty();
    assertThat(receiver.components).hasSize(1);
    assertThat(receiver.components.get(0).location).isEqualTo(target);
    assertThat(receiver.components.get(0).component.name).isEqualTo("library");
    assertThat(receiver.components.get(0).component.hash).isNull();
  }

  @Test
  void productionPublishesCurrentLoadedOriginsWithoutScanningUnusedLibraries(@TempDir Path temp)
      throws Exception {
    Path artifact =
        archive(
            temp,
            "application.jar",
            mapOf(
                "META-INF/maven/org.example/application/pom.properties",
                    bytes("groupId=org.example\nartifactId=application\nversion=1.0\n"),
                "BOOT-INF/lib/unloaded.jar", new byte[8192],
                "BOOT-INF/lib/library.jar",
                    mavenJarBytes("org.example", "library", "2.0", "payload")));
    System.setProperty("beacon.security.local-output.enabled", "false");
    System.setProperty("beacon.security.sbom.max.archive.bytes", "1024");
    System.setProperty("java.class.path", temp.resolve("missing-classpath.jar").toString());
    URL root = artifact.toUri().toURL();
    Class<?> application = typeAt(new URL(root + "!/BOOT-INF/classes/"));
    Class<?> library = typeAt(new URL(root + "!/BOOT-INF/lib/library.jar!/"));
    AtomicReference<Class<?>[]> observed = new AtomicReference<>(new Class<?>[] {application});
    List<Map<String, Object>> events = new ArrayList<>();
    try (SbomInventory inventory = new SbomInventory(instrumentation(observed), events::add)) {
      inventory.refresh();
      assertThat(events.get(0).get("dependencies"))
          .isEqualTo(singletonList(dependency("org.example:application", "1.0")));

      observed.set(new Class<?>[] {application, library});
      inventory.refresh();
      assertThat((List<?>) events.get(1).get("dependencies")).hasSize(2);
      assertThat(inventory.resolve(application.getName(), application.getClassLoader()))
          .containsEntry("name", "org.example:application");
      assertThat(inventory.resolve(library.getName(), library.getClassLoader()))
          .containsEntry("name", "org.example:library");

      observed.set(new Class<?>[] {library});
      inventory.refresh();
      assertThat(events.get(2).get("dependencies"))
          .isEqualTo(singletonList(dependency("org.example:library", "2.0")));
      assertThat(inventory.resolve(application.getName(), application.getClassLoader())).isEmpty();

      observed.set(new Class<?>[0]);
      inventory.refresh();
      assertThat(events).hasSize(4);
      assertThat(events.get(3).get("dependencies")).isEqualTo(emptyList());
    }
  }

  @Test
  void productionReusesKnownOriginsWhileResolvingNewLibraries(@TempDir Path temp) throws Exception {
    Path first = mavenJar(temp, "first.jar", "org.example", "first", "1.0", "payload");
    Path second =
        archive(
            temp,
            "second.jar",
            mapOf(
                "META-INF/maven/org.example/second/pom.properties",
                bytes("groupId=org.example\nartifactId=second\nversion=1.0\n")));
    System.setProperty("beacon.security.local-output.enabled", "false");
    Class<?> firstType = typeAt(first.toUri().toURL());
    Class<?> secondType = typeAt(second.toUri().toURL());
    AtomicReference<Class<?>[]> observed = new AtomicReference<>(new Class<?>[] {firstType});
    List<Map<String, Object>> events = new ArrayList<>();
    try (SbomInventory inventory = new SbomInventory(instrumentation(observed), events::add)) {
      inventory.refresh();
      // Re-reading the first JAR would exceed this budget; the newly loaded JAR has one entry.
      System.setProperty("beacon.security.sbom.max.entries", "1");
      observed.set(new Class<?>[] {firstType, secondType});
      inventory.refresh();
      inventory.refresh();

      assertThat(events).hasSize(3);
      assertThat((List<?>) events.get(1).get("dependencies")).hasSize(2);
      assertThat(events.get(2).get("dependencies")).isEqualTo(events.get(1).get("dependencies"));
      assertThat(events.get(2).get("observed_at")).isNotEqualTo(events.get(1).get("observed_at"));
    }
  }

  @Test
  void productionExcludesLibrariesInsideTheAgentArchive(@TempDir Path temp) throws IOException {
    Path application =
        mavenJar(temp, "application.jar", "org.example", "application", "1.0", "app");
    Path agent = mavenJar(temp, "agent.jar", "io.opentelemetry", "javaagent", "1.0", "agent");
    URL agentOrigin = agent.toUri().toURL();
    Class<?> helper = typeAt(new URL(agentOrigin + "!/internal/agent-helper.jar"));
    Class<?> entry;
    try (InputStream input =
        getClass().getResourceAsStream("/io/opentelemetry/javaagent/OpenTelemetryAgent.class")) {
      assertThat(input).isNotNull();
      entry =
          new NestedSourceLoader()
              .define("io.opentelemetry.javaagent.OpenTelemetryAgent", readAll(input), agentOrigin);
    }
    Class<?> app = typeAt(application.toUri().toURL());
    System.setProperty("beacon.security.local-output.enabled", "false");
    List<Map<String, Object>> events = new ArrayList<>();
    try (SbomInventory inventory =
        new SbomInventory(instrumentation(helper, app, entry), events::add)) {
      inventory.refresh();

      assertThat(events).hasSize(1);
      assertThat(events.get(0).get("dependencies"))
          .isEqualTo(singletonList(dependency("org.example:application", "1.0")));
    }
  }

  @Test
  void productionInvalidatesReplacedOriginsWithoutAttributingNewBytesToLoadedClasses(
      @TempDir Path temp) throws Exception {
    Path artifact = mavenJar(temp, "application.jar", "org.example", "first", "1.0", "first");
    Path replacement = mavenJar(temp, "replacement.jar", "org.example", "second", "2.0", "longer");
    System.setProperty("beacon.security.local-output.enabled", "false");
    Class<?> loaded = typeAt(artifact.toUri().toURL());
    List<Map<String, Object>> events = new ArrayList<>();
    try (SbomInventory inventory = new SbomInventory(instrumentation(loaded), events::add)) {
      inventory.refresh();
      assertThat(inventory.resolve(loaded.getName(), loaded.getClassLoader()))
          .containsEntry("name", "org.example:first");

      Files.copy(replacement, artifact, StandardCopyOption.REPLACE_EXISTING);
      inventory.refresh();

      assertThat(events).hasSize(2);
      assertThat(events.get(1).get("dependencies")).isEqualTo(emptyList());
      assertThat(inventory.resolve(loaded.getName(), loaded.getClassLoader())).isEmpty();
    }
  }

  @Test
  void failedCachesRetryWithoutWaitingForExpiration(@TempDir Path temp) throws IOException {
    Path artifact = mavenJar(temp, "library.jar", "org.example", "library", "1.0", "payload");
    System.setProperty("beacon.security.local-output.enabled", "false");
    System.setProperty("beacon.security.sbom.max.scan.bytes", "1");
    String fingerprint = ArtifactCache.fingerprint(artifact);
    ArtifactCache failed = new ArtifactCache(artifact, fingerprint);
    assertThat(failed.reusable(fingerprint)).isFalse();

    System.setProperty("beacon.security.sbom.max.scan.bytes", "65536");
    ArtifactCache recovered = new ArtifactCache(artifact, fingerprint);
    assertThat(recovered.reusable(fingerprint)).isTrue();
    RecordingReceiver receiver = new RecordingReceiver();
    recovered.replay(receiver);
    assertThat(receiver.incomplete).isEmpty();
    assertThat(receiver.components).hasSize(1);
  }

  private Class<?> typeAt(URL source) throws IOException {
    try (InputStream input =
        getClass().getResourceAsStream("/sample/dynamic/DynamicFixture.class")) {
      assertThat(input).isNotNull();
      return new NestedSourceLoader()
          .define("sample.dynamic.DynamicFixture", readAll(input), source);
    }
  }

  private static Map<String, Object> dependency(String name, String version) {
    return Values.map(
        "name", name, "version", version, "hash", DependencyInventory.identityHash(name, version));
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "tomcat-embed-core",
        "tomcat-embed-el",
        "tomcat-embed-jasper",
        "tomcat-embed-websocket"
      })
  void preservesArtifactNamesWhenManifestTitlesAreShared(String artifactId, @TempDir Path temp)
      throws IOException {
    Path artifact =
        archive(
            temp,
            artifactId + "-9.0.55.jar",
            mapOf(
                "META-INF/MANIFEST.MF",
                bytes(
                    "Manifest-Version: 1.0\r\nImplementation-Title: Apache Tomcat\r\nImplementation-Version: 9.0.55\r\n\r\n")));
    System.setProperty("beacon.security.local-output.enabled", "false");

    RecordingReceiver receiver = scan(artifact);

    assertThat(receiver.components).hasSize(1);
    Component component = receiver.components.get(0).component;
    assertThat(component.name).isEqualTo(artifactId);
    assertThat(component.version).isEqualTo("9.0.55");
    assertThat(component.hash).isNull();
    assertThat(DependencyInventory.dependency(component.json()))
        .isEqualTo(dependency(artifactId, "9.0.55"));
  }

  @Test
  void usesMatchingMavenCoordinatesForTheOuterShadedArtifact(@TempDir Path temp)
      throws IOException {
    Path artifact =
        archive(
            temp,
            "mybatis-3.5.7.jar",
            mapOf(
                "META-INF/maven/org.javassist/javassist/pom.properties",
                    bytes("groupId=org.javassist\nartifactId=javassist\nversion=3.27.0\n"),
                "META-INF/maven/org.mybatis/mybatis/pom.properties",
                    bytes("groupId=org.mybatis\nartifactId=mybatis\nversion=3.5.7\n")));
    System.setProperty("beacon.security.local-output.enabled", "false");

    RecordingReceiver receiver = scan(artifact);

    Record primary = find(receiver.components, "mybatis");
    assertThat(primary).isNotNull();
    assertThat(primary.primary).isTrue();
    assertThat(DependencyInventory.dependency(primary.component.json()))
        .isEqualTo(dependency("org.mybatis:mybatis", "3.5.7"));
    assertThat(find(receiver.components, "javassist").primary).isFalse();
  }

  private static RecordingReceiver scan(Path path) {
    RecordingReceiver receiver = new RecordingReceiver();
    new ArchiveScanner(receiver).scan(path);
    return receiver;
  }

  private static void zeroCentralDirectoryField(Path path, int offset) throws IOException {
    byte[] data = Files.readAllBytes(path);
    for (int i = 0; i + 46 <= data.length; i++) {
      if (data[i] == 'P' && data[i + 1] == 'K' && data[i + 2] == 1 && data[i + 3] == 2) {
        Arrays.fill(data, i + offset, i + offset + 4, (byte) 0);
        Files.write(path, data);
        return;
      }
    }
    throw new IOException("ZIP central directory not found");
  }

  @Test
  void compactSnapshotUsesCoordinateHashesAndSplitsWithoutLosingDependencies() throws Exception {
    System.setProperty("beacon.security.evidence.max.bytes", "2048");
    List<Map<String, Object>> records = new ArrayList<>();
    for (int i = 0; i < 150; i++) {
      Component component =
          new Component("library-" + i + "-中文", "org.example", "1.0", "aabb", "maven-metadata");
      component.loaded = true;
      records.add(component.json());
    }
    Component fallback = new Component("no-metadata", "", "2.0", "abcd", "filename");
    fallback.loaded = true;
    records.add(fallback.json());
    records.add(fallback.json());
    records.add(new Component("not-loaded", "org.example", "1.0", "ffff", "maven-metadata").json());
    List<Map<String, Object>> parts =
        DependencyInventory.events(
            Values.map(
                "event_name", "beacon.security.sbom.inventory",
                "started_at", "2026-10-27T09:00:00.000Z",
                "uptime_ms", 123456L),
            records);
    assertTrue(parts.size() > 1);
    List<Object> dependencies = new ArrayList<>();
    for (int i = 0; i < parts.size(); i++) {
      Map<String, Object> part = parts.get(i);
      assertEquals(i, part.get("part_index"));
      assertEquals(parts.size(), part.get("part_count"));
      assertThat(part)
          .containsEntry("started_at", "2026-10-27T09:00:00.000Z")
          .containsEntry("uptime_ms", 123456L);
      assertTrue(json.writeValueAsBytes(part).length <= 2048);
      dependencies.addAll((List<?>) part.get("dependencies"));
    }
    assertEquals(151, dependencies.size());
    assertTrue(dependencies.contains(dependency("no-metadata", "2.0")));
    List<Map<String, Object>> empty =
        DependencyInventory.events(
            Values.map("event_name", "beacon.security.sbom.inventory"), emptyList());
    assertEquals(emptyList(), empty.get(0).get("dependencies"));
  }

  @Test
  void defaultIntervalDoesNotKeepTheOldFiveSecondRefresh() throws Exception {
    System.clearProperty("beacon.security.sbom.refresh.seconds");
    System.setProperty("beacon.security.local-output.enabled", "false");
    System.setProperty("java.class.path", "");
    CountDownLatch received = new CountDownLatch(2);
    SbomInventory inventory = new SbomInventory(instrumentation(), event -> received.countDown());
    try {
      inventory.start();
      assertThat(received.await(6, SECONDS)).isFalse();
      assertThat(received.getCount()).isEqualTo(1);
    } finally {
      inventory.close();
    }
  }

  @Test
  void configuredIntervalPublishesUnchangedDependencies(@TempDir Path temp) throws Exception {
    long uptimeBefore = ManagementFactory.getRuntimeMXBean().getUptime();
    Path artifact = mavenJar(temp, "library.jar", "org.example", "library", "1.0", "payload");
    Class<?> loaded = typeAt(artifact.toUri().toURL());
    System.setProperty("beacon.security.sbom.refresh.seconds", "1");
    System.setProperty("beacon.security.sbom.cache.seconds", "1");
    System.setProperty("beacon.security.local-output.enabled", "false");
    System.setProperty("java.class.path", "");
    List<Map<String, Object>> events = new CopyOnWriteArrayList<>();
    CountDownLatch received = new CountDownLatch(2);
    SbomInventory inventory =
        new SbomInventory(
            instrumentation(loaded),
            event -> {
              events.add(event);
              // The former cache TTL expires before the next collection. A reparse would fail.
              System.setProperty("beacon.security.sbom.max.entries", "1");
              received.countDown();
            });
    try {
      inventory.start();
      assertThat(received.await(5, SECONDS)).isTrue();
      assertThat(events).hasSizeGreaterThanOrEqualTo(2);
      assertThat(events.get(0))
          .containsEntry("dependencies", singletonList(dependency("org.example:library", "1.0")))
          .doesNotContainKeys("status", "error");
      assertThat(events.get(1))
          .containsEntry("dependencies", events.get(0).get("dependencies"))
          .doesNotContainKeys("revision", "sbom_id", "release_id", "part_index", "part_count");
      assertThat(events.get(1).get("observed_at")).isNotEqualTo(events.get(0).get("observed_at"));
      String startedAt = Events.timestamp(ManagementFactory.getRuntimeMXBean().getStartTime());
      assertThat(events.get(0)).containsEntry("started_at", startedAt);
      assertThat(events.get(1)).containsEntry("started_at", startedAt);
      long firstUptime = ((Number) events.get(0).get("uptime_ms")).longValue();
      long secondUptime = ((Number) events.get(1).get("uptime_ms")).longValue();
      assertThat(firstUptime).isGreaterThanOrEqualTo(uptimeBefore);
      assertThat(secondUptime)
          .isGreaterThan(firstUptime)
          .isLessThanOrEqualTo(ManagementFactory.getRuntimeMXBean().getUptime());
    } finally {
      inventory.close();
    }
  }

  @Test
  void repeatedFailuresDoNotPublishAnEmptySuccessfulInventory() throws Exception {
    System.setProperty("beacon.security.sbom.refresh.seconds", "1");
    System.setProperty("beacon.security.local-output.enabled", "false");
    System.setProperty("java.class.path", "");
    List<Map<String, Object>> events = new CopyOnWriteArrayList<>();
    CountDownLatch received = new CountDownLatch(2);
    SbomInventory inventory =
        new SbomInventory(
            null,
            event -> {
              events.add(event);
              received.countDown();
            });
    try {
      inventory.start();
      assertThat(received.await(3, SECONDS)).isFalse();
      assertThat(events).isEmpty();
      assertThat(inventory.health()).containsEntry("status", "error");
    } finally {
      inventory.close();
    }
  }

  private static SbomInventory inventory(
      Path output, List<Map<String, Object>> events, Instrumentation instrumentation) {
    System.setProperty("beacon.security.sbom.output", output.toString());
    return new SbomInventory(
        instrumentation == null ? instrumentation() : instrumentation, events::add);
  }

  private static void restore(String key, String value) {
    if (value == null) {
      System.clearProperty(key);
    } else {
      System.setProperty(key, value);
    }
  }

  private static Instrumentation instrumentation(Class<?>... loaded) {
    return (Instrumentation)
        Proxy.newProxyInstance(
            SbomInventoryBehaviorTest.class.getClassLoader(),
            new Class<?>[] {Instrumentation.class},
            (proxy, method, args) -> {
              if (method.getName().equals("getAllLoadedClasses")) {
                return loaded;
              }
              if (method.getReturnType() == boolean.class) {
                return false;
              }
              if (method.getReturnType() == int.class) {
                return 0;
              }
              return null;
            });
  }

  private static Instrumentation instrumentation(AtomicReference<Class<?>[]> loaded) {
    return (Instrumentation)
        Proxy.newProxyInstance(
            SbomInventoryBehaviorTest.class.getClassLoader(),
            new Class<?>[] {Instrumentation.class},
            (proxy, method, args) -> {
              if (method.getName().equals("getAllLoadedClasses")) {
                return loaded.get();
              }
              if (method.getReturnType() == boolean.class) {
                return false;
              }
              if (method.getReturnType() == int.class) {
                return 0;
              }
              return null;
            });
  }

  private Path dynamicJar(Path temp) throws Exception {
    return dynamicJar(temp, "dynamic-loaded.jar", "dynamic");
  }

  private Path dynamicJar(Path temp, String name, String marker) throws Exception {
    String resourceName = "/sample/dynamic/DynamicFixture.class";
    byte[] classBytes;
    try (InputStream input = getClass().getResourceAsStream(resourceName)) {
      assertNotNull(input, "dynamic fixture class must be available in test output");
      classBytes = readAll(input);
    }
    Map<String, byte[]> entries = new LinkedHashMap<>();
    entries.put(
        "META-INF/maven/org.dynamic/dynamic-loaded/pom.properties",
        bytes("groupId=org.dynamic\nartifactId=dynamic-loaded\nversion=9.0.0\n"));
    entries.put(
        "META-INF/maven/org.dynamic/dynamic-loaded/pom.xml",
        bytes(
            "<project><licenses><license><name>Apache-2.0</name></license></licenses></project>"));
    entries.put("sample/dynamic/DynamicFixture.class", classBytes);
    entries.put("META-INF/validation-marker.txt", bytes(marker));
    return archive(temp, name, entries);
  }

  private static Path mavenJar(
      Path temp, String name, String group, String artifact, String version, String payload)
      throws IOException {
    Map<String, byte[]> entries = new LinkedHashMap<>();
    entries.put(
        "META-INF/maven/" + group + "/" + artifact + "/pom.properties",
        bytes("groupId=" + group + "\nartifactId=" + artifact + "\nversion=" + version + "\n"));
    entries.put(
        "META-INF/maven/" + group + "/" + artifact + "/pom.xml",
        bytes(
            "<project><licenses><license><name>Apache-2.0</name></license></licenses></project>"));
    entries.put("payload.txt", bytes(payload));
    return archive(temp, name, entries);
  }

  private static byte[] mavenJarBytes(String group, String artifact, String version, String payload)
      throws IOException {
    Path temp = Files.createTempFile("sbom-test-", ".jar");
    try {
      return Files.readAllBytes(
          mavenJar(
              temp.getParent(), temp.getFileName().toString(), group, artifact, version, payload));
    } finally {
      Files.deleteIfExists(temp);
    }
  }

  private static Path archive(Path temp, String name, Map<String, byte[]> entries)
      throws IOException {
    Path path = temp.resolve(name);
    Files.createDirectories(path.getParent());
    try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(path))) {
      for (Map.Entry<String, byte[]> entry : entries.entrySet()) {
        output.putNextEntry(new ZipEntry(entry.getKey()));
        output.write(entry.getValue());
        output.closeEntry();
      }
    }
    return path;
  }

  private static Record find(List<Record> records, String name) {
    for (Record record : records) {
      if (record.component.name.equals(name)) {
        return record;
      }
    }
    return null;
  }

  private static Map<String, Object> read(Path output) throws IOException {
    return new ObjectMapper()
        .readValue(output.toFile(), new TypeReference<Map<String, Object>>() {});
  }

  private static void assertCycloneDx1_7(Map<String, Object> document) {
    assertEquals("CycloneDX", document.get("bomFormat"));
    assertEquals("1.7", document.get("specVersion"));
    assertTrue(document.get("serialNumber") instanceof String);
    assertTrue(String.valueOf(document.get("serialNumber")).startsWith("urn:uuid:"));
    assertTrue(document.get("version") instanceof Number);
    assertTrue(((Number) document.get("version")).intValue() > 0);
    assertTrue(document.get("components") instanceof List);
    assertTrue(document.get("dependencies") instanceof List);
  }

  @Nullable
  @SuppressWarnings("unchecked")
  private static Map<String, Object> component(Map<String, Object> document, String name) {
    Object value = document.get("components");
    if (!(value instanceof List)) {
      return null;
    }
    for (Object entry : (List<Object>) value) {
      if (entry instanceof Map && name.equals(((Map<String, Object>) entry).get("name"))) {
        return (Map<String, Object>) entry;
      }
    }
    return null;
  }

  @SuppressWarnings("unchecked")
  private static String property(Map<String, Object> component, String name) {
    Object values = component.get("properties");
    if (!(values instanceof List)) {
      return null;
    }
    for (Object value : (List<Object>) values) {
      if (value instanceof Map && name.equals(((Map<String, Object>) value).get("name"))) {
        return String.valueOf(((Map<String, Object>) value).get("value"));
      }
    }
    return null;
  }

  @SuppressWarnings("unchecked")
  private static String documentProperty(Map<String, Object> document, String name) {
    Object values = document.get("properties");
    if (!(values instanceof List)) {
      return null;
    }
    for (Object value : (List<Object>) values) {
      if (value instanceof Map && name.equals(((Map<String, Object>) value).get("name"))) {
        return String.valueOf(((Map<String, Object>) value).get("value"));
      }
    }
    return null;
  }

  @Nullable
  @SuppressWarnings("unchecked")
  private static Map<String, Object> event(
      List<Map<String, Object>> events, String eventName, String key, Object value) {
    for (Map<String, Object> candidate : events) {
      if (eventName.equals(candidate.get("event_name")) && value.equals(candidate.get(key))) {
        return candidate;
      }
    }
    return null;
  }

  @SuppressWarnings("unchecked")
  private static String licenseName(Map<String, Object> component) {
    Object values = component.get("licenses");
    if (!(values instanceof List) || ((List<?>) values).isEmpty()) {
      return null;
    }
    Object first = ((List<?>) values).get(0);
    if (!(first instanceof Map)) {
      return null;
    }
    Object license = ((Map<?, ?>) first).get("license");
    if (!(license instanceof Map)) {
      return null;
    }
    return String.valueOf(((Map<?, ?>) license).get("name"));
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> quality(Map<String, Object> document) throws IOException {
    String value = documentProperty(document, "beacon:security:sbom:quality");
    return value == null ? emptyMap() : new ObjectMapper().readValue(value, Map.class);
  }

  @SuppressWarnings("unchecked")
  private static String completenessReasons(Map<String, Object> document) {
    Object values = document.get("properties");
    if (!(values instanceof List)) {
      return "";
    }
    for (Object value : (List<Object>) values) {
      if (value instanceof Map
          && "beacon:security:sbom:completeness-reasons"
              .equals(((Map<String, Object>) value).get("name"))) {
        return String.valueOf(((Map<String, Object>) value).get("value"));
      }
    }
    return "";
  }

  @SuppressWarnings("unchecked")
  private static String applicationComponentRef(Map<String, Object> document) {
    Map<String, Object> metadata = (Map<String, Object>) document.get("metadata");
    Map<String, Object> component = (Map<String, Object>) metadata.get("component");
    return String.valueOf(component.get("bom-ref"));
  }

  @SuppressWarnings("unchecked")
  private static boolean containsDependency(List<?> dependencies, String ref, String target) {
    for (Object value : dependencies) {
      if (!(value instanceof Map)) {
        continue;
      }
      Map<String, Object> dependency = (Map<String, Object>) value;
      if (!ref.equals(dependency.get("ref"))) {
        continue;
      }
      Object targets = dependency.get("dependsOn");
      return targets instanceof List && ((List<Object>) targets).contains(target);
    }
    return false;
  }

  private static String stringValue(Object value) {
    return value == null ? null : String.valueOf(value);
  }

  private static byte[] bytes(String value) {
    return value.getBytes(UTF_8);
  }

  private static byte[] readAll(InputStream input) throws IOException {
    ByteArrayOutputStream output = new ByteArrayOutputStream();
    byte[] buffer = new byte[8192];
    int count;
    while ((count = input.read(buffer)) >= 0) {
      output.write(buffer, 0, count);
    }
    return output.toByteArray();
  }

  private static Map<String, byte[]> mapOf(Object... pairs) {
    Map<String, byte[]> result = new LinkedHashMap<>();
    for (int i = 0; i < pairs.length; i += 2) {
      result.put(String.valueOf(pairs[i]), (byte[]) pairs[i + 1]);
    }
    return result;
  }

  private static Map<String, Object> mapOfObjects(Object... pairs) {
    Map<String, Object> result = new LinkedHashMap<>();
    for (int i = 0; i < pairs.length; i += 2) {
      result.put(String.valueOf(pairs[i]), pairs[i + 1]);
    }
    return result;
  }

  private static final class Record {
    final Component component;
    final String location;
    final boolean primary;

    Record(Component component, String location, boolean primary) {
      this.component = component;
      this.location = location;
      this.primary = primary;
    }
  }

  private static final class RecordingReceiver implements ArchiveScanner.Receiver {
    final List<Record> components = new ArrayList<>();
    final List<Map<String, Object>> imported = new ArrayList<>();
    final List<String> incomplete = new ArrayList<>();

    RecordingReceiver() {}

    @Override
    public void component(Component component, String location, boolean primary) {
      components.add(new Record(component, location, primary));
    }

    @Override
    public void imported(String location, Map<String, Object> bom) {
      imported.add(bom);
    }

    @Override
    public void incomplete(String reason) {
      incomplete.add(reason);
    }
  }

  private static final class CoordinatedLoader extends URLClassLoader {
    private static final String TARGET = "sample.dynamic.DynamicFixture";
    final CountDownLatch entered = new CountDownLatch(1);
    final CountDownLatch release = new CountDownLatch(1);
    volatile boolean gate;

    CoordinatedLoader(Path artifact, boolean gate) throws IOException {
      super(new URL[] {artifact.toUri().toURL()}, null);
      this.gate = gate;
    }

    @Override
    protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
      if (gate && TARGET.equals(name)) {
        entered.countDown();
        try {
          if (!release.await(5, SECONDS)) {
            throw new ClassNotFoundException("resolve gate timeout");
          }
        } catch (InterruptedException error) {
          Thread.currentThread().interrupt();
          throw new ClassNotFoundException("resolve gate interrupted", error);
        }
      }
      return super.loadClass(name, resolve);
    }
  }

  private static final class NestedSourceLoader extends ClassLoader {
    NestedSourceLoader() {
      super(null);
    }

    Class<?> define(String name, byte[] bytes, URL location) {
      ProtectionDomain domain =
          new ProtectionDomain(new CodeSource(location, (Certificate[]) null), null, this, null);
      return defineClass(name, bytes, 0, bytes.length, domain);
    }
  }
}

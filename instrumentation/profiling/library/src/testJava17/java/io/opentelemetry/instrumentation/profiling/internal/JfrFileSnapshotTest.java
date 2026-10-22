/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.instrumentation.profiling.internal;

import static java.util.Collections.singletonList;
import static java.util.stream.Collectors.toList;
import static org.assertj.core.api.Assertions.assertThat;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.util.List;
import jdk.jfr.AnnotationElement;
import jdk.jfr.Event;
import jdk.jfr.EventFactory;
import jdk.jfr.Name;
import jdk.jfr.Recording;
import jdk.jfr.ValueDescriptor;
import jdk.jfr.consumer.RecordingFile;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class JfrFileSnapshotTest {
  private static final EventFactory MARKERS =
      EventFactory.create(
          singletonList(new AnnotationElement(Name.class, "beacon.TestMarker")),
          singletonList(new ValueDescriptor(int.class, "value")));
  @TempDir Path directory;

  @Test
  void detachedSnapshotExcludesPreviouslyExportedChunksAndRemainsReadable() throws Exception {
    Assumptions.assumeTrue(JfrSupport.isJfrAvailable());
    Path whole = directory.resolve("whole.jfr");
    Path filtered = directory.resolve("filtered.jfr");
    Path earlier = directory.resolve("earlier.jfr");
    Path later = directory.resolve("later.jfr");
    try (Recording recording = new Recording()) {
      recording.enable("beacon.TestMarker").withoutStackTrace();
      recording.start();
      marker(1);
      recording.stop();
      recording.dump(earlier);
    }
    // Separate chunks by a clear wall-clock boundary, independent of JDK clock precision.
    Thread.sleep(20);
    Instant cursor = Instant.now();
    Instant end;
    try (Recording recording = new Recording()) {
      recording.enable("beacon.TestMarker").withoutStackTrace();
      recording.start();
      marker(2);
      recording.stop();
      end = recording.getStopTime();
      recording.dump(later);
    }
    Files.copy(earlier, whole);
    Files.write(whole, Files.readAllBytes(later), StandardOpenOption.APPEND);
    try (JfrFileSnapshot snapshot = new JfrFileSnapshot(whole, cursor, end);
        InputStream input = snapshot.openStream()) {
      assertThat(input).isNotNull();
      Files.copy(input, filtered);
    }
    List<Integer> values =
        RecordingFile.readAllEvents(filtered).stream()
            .filter(event -> event.getEventType().getName().equals("beacon.TestMarker"))
            .map(event -> event.getInt("value"))
            .collect(toList());
    assertThat(values).containsExactly(2);
    assertThat(whole).doesNotExist();
  }

  @Test
  void futureIntervalReturnsNoStream() throws Exception {
    Assumptions.assumeTrue(JfrSupport.isJfrAvailable());
    Path file = directory.resolve("empty-interval.jfr");
    try (Recording recording = new Recording()) {
      recording.enable("beacon.TestMarker");
      recording.start();
      marker(1);
      recording.stop();
      recording.dump(file);
    }
    Instant future = Instant.now().plusSeconds(60);
    try (JfrFileSnapshot snapshot = new JfrFileSnapshot(file, future, future.plusSeconds(1));
        InputStream input = snapshot.openStream()) {
      assertThat(input).isNull();
    }
  }

  private static void marker(int value) {
    Event marker = MARKERS.newEvent();
    marker.set(0, value);
    assertThat(marker.isEnabled()).isTrue();
    marker.commit();
  }
}

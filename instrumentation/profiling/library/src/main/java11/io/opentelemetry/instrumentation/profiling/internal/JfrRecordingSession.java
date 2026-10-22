/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.instrumentation.profiling.internal;

import static java.util.logging.Level.FINE;
import static java.util.logging.Level.WARNING;

import io.opentelemetry.instrumentation.profiling.ProfileSnapshot;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.text.ParseException;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Supplier;
import java.util.logging.Logger;
import javax.annotation.Nullable;
import jdk.jfr.Configuration;
import jdk.jfr.FlightRecorder;
import jdk.jfr.FlightRecorderListener;
import jdk.jfr.Recording;
import jdk.jfr.RecordingState;

final class JfrRecordingSession implements AutoCloseable {

  private final Recording recording;
  private final Object handoff = new Object();
  private final FlightRecorderListener listener;
  @Nullable private final Path tempDir;
  @Nullable private JfrFileSnapshot detached;
  private boolean closed;
  @Nullable private volatile Thread stoppingThread;
  private static final Logger logger = Logger.getLogger(JfrRecordingSession.class.getName());

  JfrRecordingSession(ProfilingConfig config) {
    this(config, null);
  }

  JfrRecordingSession(ProfilingConfig config, @Nullable Supplier<Instant> cursor) {
    this.recording = createRecording(config);
    this.tempDir = config.getTempDir();
    listener =
        new FlightRecorderListener() {
          @Override
          public void recordingStateChanged(Recording changed) {
            if (cursor != null
                && changed == recording
                && changed.getState() == RecordingState.STOPPED
                && Thread.currentThread() != stoppingThread) {
              detach(cursor.get());
            }
          }
        };
    if (cursor != null) {
      FlightRecorder.addListener(listener);
    }
  }

  void start() {
    recording.start();
  }

  JfrProfileSnapshot snapshot(Instant startTime) {
    Recording snapshot = FlightRecorder.getFlightRecorder().takeSnapshot();
    snapshot.setName(recording.getName());
    return JfrProfileSnapshot.create(snapshot, startTime);
  }

  ProfileSnapshot stop(Instant startTime) {
    JfrFileSnapshot fallback = null;
    try (JfrProfileSnapshot snapshot = snapshot(startTime);
        InputStream input = snapshot.openStream()) {
      if (input != null) {
        fallback = preserve(input, startTime, snapshot.getEndTime());
      }
    } catch (IOException | RuntimeException failure) {
      logger.log(FINE, "JFR stopped before the final backup snapshot", failure);
    }
    stoppingThread = Thread.currentThread();
    try {
      recording.stop();
    } catch (IllegalStateException exception) {
      if (recording.getStopTime() == null) {
        delete(fallback);
        throw exception;
      }
    } finally {
      stoppingThread = null;
    }
    JfrFileSnapshot captured = null;
    synchronized (handoff) {
      if (detached != null) {
        captured = detached.startingAt(startTime);
        detached = null;
      }
    }
    if (captured != null) {
      delete(fallback);
      return captured;
    }
    try {
      Instant end = recording.getStopTime();
      try (InputStream input = recording.getStream(startTime, end)) {
        if (input != null) {
          JfrFileSnapshot snapshot = preserve(input, startTime, end);
          delete(fallback);
          return snapshot;
        }
      }
    } catch (IOException | RuntimeException failure) {
      logger.log(
          FINE, "JFR shutdown removed the stopped recording; using its detached snapshot", failure);
    }
    if (fallback != null) {
      return fallback;
    }
    return JfrProfileSnapshot.create(recording, startTime);
  }

  private JfrFileSnapshot preserve(InputStream input, Instant start, Instant end)
      throws IOException {
    Path directory = tempDir;
    if (directory != null) {
      Files.createDirectories(directory);
    }
    Path file =
        directory == null
            ? Files.createTempFile("otel-profile-final-", ".jfr")
            : Files.createTempFile(directory, "otel-profile-final-", ".jfr");
    try {
      Files.copy(input, file, StandardCopyOption.REPLACE_EXISTING);
      return new JfrFileSnapshot(file, start, end);
    } catch (IOException | RuntimeException failure) {
      Files.deleteIfExists(file);
      throw failure;
    }
  }

  private static void delete(@Nullable JfrFileSnapshot snapshot) {
    if (snapshot != null) {
      try {
        snapshot.close();
      } catch (IOException failure) {
        logger.log(WARNING, "Unable to delete final JFR staging file", failure);
      }
    }
  }

  @Override
  public void close() {
    FlightRecorder.removeListener(listener);
    JfrFileSnapshot pending;
    synchronized (handoff) {
      closed = true;
      pending = detached;
      detached = null;
    }
    if (pending != null) {
      try {
        pending.close();
      } catch (IOException failure) {
        logger.log(WARNING, "Unable to delete final JFR staging file", failure);
      }
    }
    recording.close();
  }

  private void detach(Instant startTime) {
    // JFR may call listeners under its recorder monitor. Never wait for our worker or upload here.
    // Finish copying before returning so repository cleanup cannot invalidate lazy chunk reads.
    Path file = null;
    try {
      Instant end = recording.getStopTime();
      try (InputStream input = recording.getStream(startTime, end)) {
        if (input == null) {
          return;
        }
        Path directory = tempDir;
        if (directory != null) {
          Files.createDirectories(directory);
          file = Files.createTempFile(directory, "otel-profile-final-", ".jfr");
        } else {
          file = Files.createTempFile("otel-profile-final-", ".jfr");
        }
        Files.copy(input, file, StandardCopyOption.REPLACE_EXISTING);
      }
      synchronized (handoff) {
        if (!closed) {
          detached = new JfrFileSnapshot(file, startTime, end);
          file = null;
        }
      }
    } catch (IOException | RuntimeException failure) {
      logger.log(WARNING, "Unable to preserve externally stopped JFR data", failure);
    } finally {
      if (file != null) {
        try {
          Files.deleteIfExists(file);
        } catch (IOException failure) {
          logger.log(WARNING, "Unable to delete final JFR staging file", failure);
        }
      }
    }
  }

  private static Recording createRecording(ProfilingConfig config) {
    Recording recording = new Recording();
    recording.setName("otel-profiling");
    recording.setToDisk(true);
    if (config.getMaxSize() > 0) {
      recording.setMaxSize(config.getMaxSize());
    }
    recording.setMaxAge(config.getMaxAge());
    try {
      recording.setSettings(createSettings(config));
    } catch (IOException | ParseException exception) {
      throw new IllegalStateException("Unable to load JFR profile configuration", exception);
    }
    return recording;
  }

  static Map<String, String> createSettings(ProfilingConfig config)
      throws IOException, ParseException {
    Map<String, String> settings =
        new HashMap<>(Configuration.getConfiguration("profile").getSettings());
    applyMemorySettings(settings, config);
    return settings;
  }

  private static void applyMemorySettings(Map<String, String> settings, ProfilingConfig config) {
    applyBooleanSetting(
        settings,
        "jdk.ObjectAllocationInNewTLAB#enabled",
        config,
        config.getMemoryAllocationSampling());
    applyBooleanSetting(
        settings,
        "jdk.ObjectAllocationOutsideTLAB#enabled",
        config,
        config.getMemoryAllocationSampling());
    applyBooleanSetting(
        settings,
        "jdk.ObjectAllocationSample#enabled",
        config,
        config.getMemoryAllocationSampling());
    applyBooleanSetting(
        settings, "jdk.OldObjectSample#enabled", config, config.getMemoryOldObjectSampling());
    applyDefaultMemorySetting(settings, "jdk.ObjectCount#enabled", config);
    applyDefaultMemorySetting(settings, "jdk.ObjectCountAfterGC#enabled", config);
    applyDefaultMemorySetting(settings, "jdk.NativeMemoryUsage#enabled", config);
    applyDefaultMemorySetting(settings, "jdk.NativeMemoryUsageTotal#enabled", config);
    applyDefaultMemorySetting(settings, "jdk.GCHeapSummary#enabled", config);
  }

  private static void applyBooleanSetting(
      Map<String, String> settings, String settingName, ProfilingConfig config, Boolean value) {
    if (!config.isMemoryEnabled() && value == null) {
      return;
    }
    settings.put(settingName, Boolean.toString(value != null ? value : config.isMemoryEnabled()));
  }

  private static void applyDefaultMemorySetting(
      Map<String, String> settings, String settingName, ProfilingConfig config) {
    if (config.isMemoryEnabled()) {
      settings.put(settingName, "true");
    }
  }
}

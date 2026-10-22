// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

import java.nio.file.*;
import java.util.*;
import java.util.stream.*;
import jdk.jfr.*;
import jdk.jfr.consumer.*;

public class ProfilingShutdownProbe {
  @Name("beacon.FinalMarker")
  @StackTrace(false)
  public static class Marker extends Event {
    public int value;
  }

  @Name("beacon.UploadPayload")
  @StackTrace(false)
  public static class Payload extends Event {
    public String value;
  }

  public static void main(String[] args) throws Exception {
    Path dir = Paths.get(args[1]);
    if (args[0].equals("check")) {
      boolean found = false;
      try (Stream<Path> paths = Files.list(dir)) {
        for (Path path :
            paths.filter(p -> p.toString().endsWith(".jfr")).collect(Collectors.toList())) {
          for (RecordedEvent event : RecordingFile.readAllEvents(path)) {
            if (event.getEventType().getName().equals("beacon.FinalMarker")
                && event.getInt("value") == 42) found = true;
          }
        }
      }
      if (!found) throw new AssertionError("final marker missing");
      System.out.println("FINAL_MARKER_PRESENT");
      return;
    }
    if (args[0].equals("slow")) {
      Marker ready = new Marker();
      long limit = System.nanoTime() + 10_000_000_000L;
      while (!ready.isEnabled() && System.nanoTime() < limit) Thread.sleep(25);
      if (!ready.isEnabled()) throw new AssertionError("profiling did not start");
      char[] data = new char[32000];
      Arrays.fill(data, 'x');
      for (int i = 0; i < 256; i++) {
        Payload payload = new Payload();
        payload.value = i + new String(data);
        payload.commit();
      }
      Thread.sleep(2000);
      System.out.println("EXITING");
      System.exit(0);
    }
    Files.createDirectories(dir);
    long deadline = System.nanoTime() + 20_000_000_000L;
    while (System.nanoTime() < deadline) {
      boolean ready;
      try (Stream<Path> paths = Files.list(dir)) {
        ready = paths.anyMatch(p -> p.toString().endsWith(".jfr"));
      }
      if (ready) break;
      Thread.sleep(25);
    }
    try (Stream<Path> paths = Files.list(dir)) {
      if (paths.noneMatch(p -> p.toString().endsWith(".jfr"))) {
        throw new AssertionError("periodic export did not complete");
      }
    }
    Marker marker = new Marker();
    if (!marker.isEnabled()) throw new AssertionError("JFR marker disabled");
    marker.value = 42;
    marker.commit();
    System.out.println("MARKER_COMMITTED");
    Thread.sleep(50);
    System.exit(0);
  }
}

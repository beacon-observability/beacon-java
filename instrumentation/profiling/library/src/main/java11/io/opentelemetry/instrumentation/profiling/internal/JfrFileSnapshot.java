/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.instrumentation.profiling.internal;

import io.opentelemetry.instrumentation.profiling.ProfileSnapshot;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import javax.annotation.Nullable;

/** Detached JFR chunks survive the JDK shutdown hook clearing its recording repository. */
final class JfrFileSnapshot implements ProfileSnapshot {
  private final Path file;
  private final Instant start;
  private final Instant end;

  JfrFileSnapshot(Path file, Instant start, Instant end) {
    this.file = file;
    this.start = start;
    this.end = end;
  }

  JfrFileSnapshot startingAt(Instant value) {
    return new JfrFileSnapshot(file, value, end);
  }

  @Override
  public Instant getStartTime() {
    return start;
  }

  @Override
  public Instant getEndTime() {
    return end;
  }

  @Override
  public String getFormat() {
    return "jfr";
  }

  @Override
  @Nullable
  public InputStream openStream() throws IOException {
    ChunkStream stream = new ChunkStream(file, start, end);
    try {
      if (stream.next()) {
        return stream;
      }
    } catch (IOException failure) {
      stream.close();
      throw failure;
    }
    stream.close();
    return null;
  }

  @Override
  public void close() throws IOException {
    Files.deleteIfExists(file);
  }

  /** JFR 1.x/2.x chunks are self-contained. Copy complete overlapping chunks, as getStream does. */
  private static final class ChunkStream extends InputStream {
    private static final int HEADER_SIZE = 68;
    private static final int MAGIC = 0x464c5200;
    private final FileChannel channel;
    private final Instant start;
    private final Instant end;
    private long nextPosition;
    private long remaining;

    ChunkStream(Path file, Instant start, Instant end) throws IOException {
      channel = FileChannel.open(file, StandardOpenOption.READ);
      this.start = start;
      this.end = end;
    }

    boolean next() throws IOException {
      while (nextPosition < channel.size()) {
        long position = nextPosition;
        channel.position(position);
        ByteBuffer header = ByteBuffer.allocate(HEADER_SIZE);
        while (header.hasRemaining()) {
          if (channel.read(header) < 0) {
            throw new EOFException("Incomplete final JFR chunk header");
          }
        }
        int version = header.getShort(4);
        long size = header.getLong(8);
        long duration = header.getLong(40);
        if (header.getInt(0) != MAGIC
            || (version != 1 && version != 2)
            || size < HEADER_SIZE
            || size > channel.size() - position
            || duration < 0) {
          throw new IOException("Invalid final JFR chunk");
        }
        nextPosition = position + size;
        Instant chunkStart = Instant.ofEpochSecond(0, header.getLong(32));
        Instant chunkEnd = chunkStart.plusNanos(duration);
        if (!chunkEnd.isBefore(start) && !chunkStart.isAfter(end)) {
          channel.position(position);
          remaining = size;
          return true;
        }
      }
      return false;
    }

    @Override
    public int read(byte[] bytes, int offset, int length) throws IOException {
      if (length == 0) {
        return 0;
      }
      if (remaining == 0 && !next()) {
        return -1;
      }
      int read = channel.read(ByteBuffer.wrap(bytes, offset, (int) Math.min(length, remaining)));
      if (read < 0) {
        throw new EOFException("Incomplete final JFR chunk");
      }
      remaining -= read;
      return read;
    }

    @Override
    public int read() throws IOException {
      byte[] value = new byte[1];
      return read(value, 0, 1) < 0 ? -1 : value[0] & 255;
    }

    @Override
    public void close() throws IOException {
      channel.close();
    }
  }
}

/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.beacon.security.core;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.stream.Stream;
import javax.annotation.Nullable;

/** Uses a short-circuiting StackWalker when available, retaining Java 8 compatibility. */
public final class StackFrames {
  @Nullable private static final Walker WALKER = Walker.create();

  public static List<Frame> capture(Predicate<StackTraceElement> include, int limit) {
    Walker walker = WALKER;
    if (walker != null) {
      try {
        return walker.capture(include, limit);
      } catch (Throwable ignored) {
        // Older/security-managed runtimes retain the original stack capture fallback.
      }
    }
    List<Frame> result = new ArrayList<>();
    for (StackTraceElement element : Thread.currentThread().getStackTrace()) {
      if (include.test(element)) {
        result.add(new Frame(element, null));
        if (result.size() >= limit) {
          break;
        }
      }
    }
    return result;
  }

  public static final class Frame {
    public final StackTraceElement element;
    @Nullable public final Class<?> type;

    public Frame(StackTraceElement element, @Nullable Class<?> type) {
      this.element = element;
      this.type = type;
    }
  }

  private static final class Walker {
    private final MethodHandle walk;
    private final MethodHandle element;
    private final MethodHandle type;

    Walker(MethodHandle walk, MethodHandle element, MethodHandle type) {
      this.walk = walk;
      this.element = element;
      this.type = type;
    }

    @Nullable
    static Walker create() {
      try {
        Class<?> walker = Class.forName("java.lang.StackWalker");
        Class<?> option = Class.forName("java.lang.StackWalker$Option");
        Object retainClasses = option.getField("RETAIN_CLASS_REFERENCE").get(null);
        Object instance = walker.getMethod("getInstance", option).invoke(null, retainClasses);
        Class<?> frame = Class.forName("java.lang.StackWalker$StackFrame");
        return new Walker(
            MethodHandles.publicLookup()
                .unreflect(walker.getMethod("walk", Function.class))
                .bindTo(instance),
            MethodHandles.publicLookup().unreflect(frame.getMethod("toStackTraceElement")),
            MethodHandles.publicLookup().unreflect(frame.getMethod("getDeclaringClass")));
      } catch (Throwable ignored) {
        return null;
      }
    }

    List<Frame> capture(Predicate<StackTraceElement> include, int limit) throws Throwable {
      Function<Stream<?>, List<Frame>> visitor =
          stream -> {
            List<Frame> result = new ArrayList<>();
            Iterator<?> frames = stream.iterator();
            while (frames.hasNext() && result.size() < limit) {
              Frame frame = frame(frames.next());
              if (include.test(frame.element)) {
                result.add(frame);
              }
            }
            return result;
          };
      // StackWalker.walk returns exactly the visitor's List<Frame>, erased by MethodHandle.
      @SuppressWarnings("unchecked")
      List<Frame> result = (List<Frame>) walk.invoke(visitor);
      return result;
    }

    private Frame frame(Object frame) {
      try {
        return new Frame((StackTraceElement) element.invoke(frame), (Class<?>) type.invoke(frame));
      } catch (Throwable failure) {
        throw new IllegalStateException("Unable to inspect stack frame", failure);
      }
    }
  }

  private StackFrames() {}
}

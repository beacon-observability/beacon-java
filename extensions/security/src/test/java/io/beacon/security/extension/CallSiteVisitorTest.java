/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.beacon.security.extension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.beacon.security.bridge.SecurityBridge;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.net.URL;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BiFunction;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.dynamic.ClassFileLocator;
import net.bytebuddy.pool.TypePool;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import sample.calls.CallSiteFixture;
import sample.calls.CallSiteOperation;
import sample.calls.FixtureConnection;

class CallSiteVisitorTest {
  @Test
  void transformedCallsKeepConstructorPrimitiveAndExceptionSemanticsWithAndWithoutCollection()
      throws Exception {
    ClassLoader loader = CallSiteFixture.class.getClassLoader();
    CallSiteVisitor visitor =
        CallSiteVisitor.forClass(TypeDescription.ForLoadedType.of(CallSiteFixture.class), loader);
    assertThat(visitor).isNotNull();
    TypeDescription description = TypeDescription.ForLoadedType.of(CallSiteFixture.class);
    ClassWriter writer = new ClassWriter(visitor.mergeWriter(0));
    byte[] original =
        ClassFileLocator.ForClassLoader.of(loader)
            .locate(CallSiteFixture.class.getName())
            .resolve();
    new ClassReader(original)
        .accept(
            visitor.wrap(
                description,
                writer,
                null,
                TypePool.Default.of(loader),
                description.getDeclaredFields(),
                description.getDeclaredMethods(),
                visitor.mergeWriter(0),
                visitor.mergeReader(0)),
            visitor.mergeReader(0));
    CallSiteOperation operation =
        (CallSiteOperation)
            new FixtureLoader(loader).define(writer.toByteArray()).getConstructor().newInstance();
    AtomicBoolean active = new AtomicBoolean();
    AtomicInteger calls = new AtomicInteger();
    AtomicReference<String> owner = new AtomicReference<>();
    BiFunction<Integer, Object[], Object> handler =
        (code, values) -> {
          if (code == 3) {
            return active.get();
          }
          if (code == 0) {
            calls.incrementAndGet();
            owner.set((String) values[0]);
            return new Object();
          }
          return null;
        };
    Field field = SecurityBridge.class.getDeclaredField("handler");
    field.setAccessible(true);
    Object previous = field.get(null);
    field.set(null, handler);
    try {
      assertThat(operation.append(new StringBuilder(), 5000).toString()).isEqualTo("5000");
      assertThat(operation.construct("text")).isEqualTo("text");
      assertThat(calls.get()).isZero();
      active.set(true);
      assertThat(operation.construct("text")).isEqualTo("text");
      assertThat(operation.append(new StringBuilder(), 5000).toString()).isEqualTo("5000");
      assertThat(calls.get()).isPositive();
      try (InputStream stream =
          operation.open(new FixtureConnection(new URL("http://unused.invalid")))) {
        assertThat(stream.read()).isEqualTo(42);
      }
      assertThat(owner.get()).isEqualTo("sample/calls/FixtureConnection");
      assertThatThrownBy(() -> operation.construct(null)).isInstanceOf(NullPointerException.class);
    } finally {
      field.set(null, previous);
    }
  }

  private static final class FixtureLoader extends ClassLoader {
    FixtureLoader(ClassLoader parent) {
      super(parent);
    }

    Class<?> define(byte[] bytes) {
      return defineClass(CallSiteFixture.class.getName(), bytes, 0, bytes.length);
    }
  }
}

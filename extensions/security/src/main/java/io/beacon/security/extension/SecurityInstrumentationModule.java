/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.beacon.security.extension;

import static io.opentelemetry.javaagent.extension.matcher.AgentElementMatchers.hasSuperType;
import static java.util.Arrays.asList;
import static java.util.Collections.singletonList;
import static net.bytebuddy.matcher.ElementMatchers.isAbstract;
import static net.bytebuddy.matcher.ElementMatchers.isBootstrapClassLoader;
import static net.bytebuddy.matcher.ElementMatchers.isMethod;
import static net.bytebuddy.matcher.ElementMatchers.nameStartsWith;
import static net.bytebuddy.matcher.ElementMatchers.named;
import static net.bytebuddy.matcher.ElementMatchers.not;

import io.beacon.security.bridge.SecurityBridge;
import io.beacon.security.core.Settings;
import io.opentelemetry.javaagent.extension.instrumentation.InstrumentationModule;
import io.opentelemetry.javaagent.extension.instrumentation.TypeInstrumentation;
import io.opentelemetry.javaagent.extension.instrumentation.TypeTransformer;
import io.opentelemetry.javaagent.extension.instrumentation.internal.ExperimentalInstrumentationModule;
import java.io.IOException;
import java.util.List;
import java.util.function.BiFunction;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.implementation.bytecode.assign.Assigner;
import net.bytebuddy.matcher.ElementMatcher;

public final class SecurityInstrumentationModule extends InstrumentationModule
    implements ExperimentalInstrumentationModule {
  static final String BRIDGE = "io.beacon.security.bridge.SecurityBridge";

  public SecurityInstrumentationModule() {
    super("beacon-security");
  }

  @Override
  public boolean defaultEnabled() {
    return Settings.enabled("beacon.security.enabled", false);
  }

  @Override
  public HelperClassStrategy helperClassStrategy() {
    return HelperClassStrategy.INJECTED;
  }

  @Override
  public List<String> getAdditionalHelperClassNames() {
    return singletonList(BRIDGE);
  }

  @Override
  public boolean isHelperClass(String name) {
    return name.equals(BRIDGE);
  }

  @Override
  public ElementMatcher.Junction<ClassLoader> classLoaderMatcher() {
    return not(isBootstrapClassLoader());
  }

  @Override
  public List<TypeInstrumentation> typeInstrumentations() {
    return asList(new Sources(), new Bodies(), new ApplicationCalls());
  }

  static void connect(TypeTransformer transformer) {
    transformer.applyTransformer(
        (builder, type, loader, module, domain) -> {
          try {
            Class<?> bridge = Class.forName(BRIDGE, true, loader);
            bridge
                .getMethod("install", BiFunction.class)
                .invoke(null, SecurityRuntime.handler(loader));
          } catch (ReflectiveOperationException error) {
            throw new IllegalStateException("Cannot connect security helper", error);
          }
          return builder;
        });
  }

  static final class ApplicationCalls implements TypeInstrumentation {
    @Override
    public ElementMatcher<TypeDescription> typeMatcher() {
      ElementMatcher.Junction<TypeDescription> matcher =
          not(
              nameStartsWith("java.")
                  .or(nameStartsWith("javax."))
                  .or(nameStartsWith("jakarta."))
                  .or(nameStartsWith("jdk."))
                  .or(nameStartsWith("sun."))
                  .or(nameStartsWith("com.sun."))
                  .or(nameStartsWith("io.opentelemetry."))
                  .or(nameStartsWith("net.bytebuddy."))
                  .or(nameStartsWith("io.beacon.security."))
                  .or(nameStartsWith("org.gradle."))
                  .or(nameStartsWith("org.slf4j."))
                  .or(nameStartsWith("ch.qos.logback.")));
      for (String prefix :
          Settings.text("beacon.security.instrumentation.exclude", "").split(",")) {
        if (!prefix.trim().isEmpty()) {
          matcher = matcher.and(not(nameStartsWith(prefix.trim())));
        }
      }
      return matcher;
    }

    @Override
    public void transform(TypeTransformer transformer) {
      connect(transformer);
      transformer.applyTransformer(
          (builder, type, loader, module, domain) -> {
            try {
              CallSiteVisitor visitor = CallSiteVisitor.forClass(type, loader);
              return visitor == null ? builder : builder.visit(visitor);
            } catch (IOException error) {
              return builder;
            }
          });
    }
  }

  static final class Sources implements TypeInstrumentation {
    @Override
    public ElementMatcher<TypeDescription> typeMatcher() {
      return hasSuperType(
          named("javax.servlet.ServletRequest").or(named("jakarta.servlet.ServletRequest")));
    }

    @Override
    public void transform(TypeTransformer transformer) {
      connect(transformer);
      transformer.applyAdviceToMethod(
          isMethod()
              .and(not(isAbstract()))
              .and(
                  named("getParameter")
                      .or(named("getParameterValues"))
                      .or(named("getParameterMap"))
                      .or(named("getHeader"))
                      .or(named("getHeaders"))
                      .or(named("getReader"))
                      .or(named("getInputStream"))),
          SourceAdvice.class.getName());
    }
  }

  static final class Bodies implements TypeInstrumentation {
    @Override
    public ElementMatcher<TypeDescription> typeMatcher() {
      return hasSuperType(
          named(
              "org.springframework.web.servlet.mvc.method.annotation.AbstractMessageConverterMethodArgumentResolver"));
    }

    @Override
    public void transform(TypeTransformer transformer) {
      connect(transformer);
      transformer.applyAdviceToMethod(
          isMethod().and(named("readWithMessageConverters")).and(not(isAbstract())),
          BodyAdvice.class.getName());
    }
  }

  public static final class SourceAdvice {
    @Advice.OnMethodExit(suppress = Throwable.class)
    public static void exit(
        @Advice.Origin("#m") String method,
        @Advice.AllArguments Object[] args,
        @Advice.Return(typing = Assigner.Typing.DYNAMIC) Object result,
        @Advice.Origin("#t.#m") String location) {
      SecurityBridge.source(method, args.length > 0 ? args[0] : null, result, location);
    }
  }

  public static final class BodyAdvice {
    @Advice.OnMethodExit(suppress = Throwable.class)
    public static void exit(
        @Advice.Return(typing = Assigner.Typing.DYNAMIC) Object result,
        @Advice.Origin("#t.#m") String location) {
      SecurityBridge.source("body", null, result, location);
    }
  }
}

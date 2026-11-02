plugins {
  id("otel.javaagent-instrumentation")
}

muzzle {
  pass {
    group.set("log4j")
    module.set("log4j")
    versions.set("[1.2,)")
    assertInverse.set(true)
  }
}

dependencies {
  // 1.2 introduces MDC and there's no version earlier than 1.2.4 available
  library("log4j:log4j:1.2.4")
}

configurations {
  // In order to test the real log4j library we need to remove the log4j transitive
  // dependency 'log4j-over-slf4j' brought in by :testing-common which would shadow
  // the log4j module under test using a proxy to slf4j instead.
  testImplementation {
    exclude("org.slf4j", "log4j-over-slf4j")
  }

  // See: https://stackoverflow.com/a/9047963/2749853
  testImplementation {
    exclude("javax.jms", "jms")
  }
}

tasks {
  test {
    jvmArgs("-Dotel.instrumentation.common.mdc.resource-attributes=service.name,telemetry.sdk.language")
  }
}

// Exercise actual layout rendering with the opt-in flag, including custom logging keys.
tasks {
  val testPatternInjection = register<Test>("testPatternInjection") {
    testClassesDirs = sourceSets.test.get().output.classesDirs
    classpath = sourceSets.test.get().runtimeClasspath
    filter { includeTestsMatching("*LogPatternTest") }
    jvmArgs("-Dotel.instrumentation.common.logging.experimental.pattern-injection.enabled=true")
  }
  val testPatternInjectionCustomKeys = register<Test>("testPatternInjectionCustomKeys") {
    testClassesDirs = sourceSets.test.get().output.classesDirs
    classpath = sourceSets.test.get().runtimeClasspath
    filter { includeTestsMatching("*LogPatternTest") }
    jvmArgs("-Dotel.instrumentation.common.logging.experimental.pattern-injection.enabled=true")
    jvmArgs("-Dotel.instrumentation.common.logging.trace-id-key=custom_trace")
    jvmArgs("-Dotel.instrumentation.common.logging.span-id-key=custom_span")
  }
  named("check") { dependsOn(testPatternInjection, testPatternInjectionCustomKeys) }
}

tasks.withType<Test>().configureEach {
  systemProperty("testLatestDeps", otelProps.testLatestDeps)
}

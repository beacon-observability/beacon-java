plugins {
  id("otel.javaagent-instrumentation")
}

muzzle {
  pass {
    group.set("ch.qos.logback")
    module.set("logback-classic")
    versions.set("[1.0.0,1.2.3]")
  }
}

testing {
  suites {
    register<JvmTestSuite>("addBaggageTest") {
      targets {
        all {
          testTask.configure {
            jvmArgs("-Dotel.instrumentation.logback-mdc.add-baggage=true")
          }
        }
      }
    }

    register<JvmTestSuite>("loggingKeysTest") {
      targets {
        all {
          testTask.configure {
            jvmArgs("-Dotel.instrumentation.common.logging.trace-id-key=trace_id_test")
            jvmArgs("-Dotel.instrumentation.common.logging.span-id-key=span_id_test")
            jvmArgs("-Dotel.instrumentation.common.logging.trace-flags-key=trace_flags_test")
          }
        }
      }
    }

    withType(JvmTestSuite::class) {
      dependencies {
        implementation("ch.qos.logback:logback-classic") {
          version {
            strictly(baseVersion("1.0.0").orLatest())
          }
        }
        if (!otelProps.testLatestDeps) {
          implementation("org.slf4j:slf4j-api") {
            version {
              strictly("1.6.4")
            }
          }
        }

        implementation(project(":instrumentation:logback:logback-mdc-1.0:testing"))
        implementation(project(":instrumentation:logback:logback-mdc-1.0:javaagent"))
      }
    }
  }
}

dependencies {
  implementation(project(":instrumentation:logback:logback-mdc-1.0:library"))

  // pin the version strictly to avoid overriding by dependencyManagement versions
  compileOnly("ch.qos.logback:logback-classic") {
    version {
      strictly("1.0.0")
    }
  }
  compileOnly("org.slf4j:slf4j-api") {
    version {
      strictly("1.6.4")
    }
  }
}

tasks {
  test {
    jvmArgs("-Dotel.instrumentation.common.mdc.resource-attributes=service.name,telemetry.sdk.language")
  }

  named("check") {
    dependsOn(testing.suites)
  }
}

// Exercise actual layout rendering with the opt-in flag, including custom logging keys.
tasks {
  val testPatternInjection = register<Test>("testPatternInjection") {
    testClassesDirs = sourceSets.test.get().output.classesDirs
    classpath = sourceSets.test.get().runtimeClasspath
    filter { includeTestsMatching("*LogPatternTest") }
    jvmArgs("-Dotel.instrumentation.logging.pattern-injection.enabled=true")
  }
  val testPatternInjectionCustomKeys = register<Test>("testPatternInjectionCustomKeys") {
    testClassesDirs = sourceSets.test.get().output.classesDirs
    classpath = sourceSets.test.get().runtimeClasspath
    filter { includeTestsMatching("*LogPatternTest") }
    environment("OTEL_INSTRUMENTATION_LOGGING_PATTERN_INJECTION_ENABLED", "true")
    jvmArgs("-Dotel.instrumentation.common.logging.trace-id-key=custom_trace")
    jvmArgs("-Dotel.instrumentation.common.logging.span-id-key=custom_span")
  }
  named("check") { dependsOn(testPatternInjection, testPatternInjectionCustomKeys) }
}

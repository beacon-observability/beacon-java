plugins {
  id("otel.javaagent-instrumentation")
}

val profilingTestOutputDir = layout.buildDirectory.dir("test-profile-output")
val profilingTestLauncher = javaToolchains.launcherFor { languageVersion.set(JavaLanguageVersion.of(11)) }
val profilingOtlpTestPort = 19529

dependencies {
  implementation(project(":instrumentation:profiling:library"))
  implementation(project(":instrumentation-api-incubator"))

  compileOnly("io.opentelemetry:opentelemetry-sdk-extension-autoconfigure")
}

otelJava {
  minJavaVersionSupported.set(JavaVersion.VERSION_11)
}

tasks {
  test {
    val outputDir = profilingTestOutputDir.get().asFile

    javaLauncher.set(profilingTestLauncher)

    filter {
      excludeTestsMatching("io.opentelemetry.javaagent.instrumentation.profiling.ProfilingOtlpExportTest")
    }

    doFirst {
      outputDir.deleteRecursively()
      outputDir.mkdirs()
    }

    environment("OTEL_PROFILING_ENABLED", "true")
    environment("OTEL_PROFILING_EXPORTER", "file")
    environment("OTEL_PROFILING_INTERVAL", "1s")
    environment("OTEL_PROFILING_STARTUP_DELAY", "0s")
    environment("OTEL_PROFILING_FILE_PATH", outputDir.absolutePath)
  }

  val otlpTest by registering(Test::class) {
    javaLauncher.set(profilingTestLauncher)
    testClassesDirs = sourceSets.test.get().output.classesDirs
    classpath = sourceSets.test.get().runtimeClasspath

    filter {
      includeTestsMatching("io.opentelemetry.javaagent.instrumentation.profiling.ProfilingOtlpExportTest")
    }

    environment("OTEL_PROFILING_ENABLED", "true")
    environment("OTEL_PROFILING_EXPORTER", "otlp")
    environment("OTEL_PROFILING_INTERVAL", "1s")
    environment("OTEL_PROFILING_STARTUP_DELAY", "2s")
    environment("OTEL_PROFILING_MEMORY_ENABLED", "true")
    systemProperty(
      "otel.profiling.endpoint",
      "http://127.0.0.1:$profilingOtlpTestPort/profiling/v1/input"
    )
    systemProperty("otel.service.name", "profiling-test-service")
    systemProperty("otel.service.version", "1.2.3")
    systemProperty(
      "otel.resource.attributes",
      "deployment.environment.name=prod,host.name=profiling-host"
    )
    systemProperty("profiling.otlp.test.port", profilingOtlpTestPort.toString())
  }

  check {
    dependsOn(otlpTest)
  }
}

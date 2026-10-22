plugins {
  id("otel.java-conventions")
}

dependencies {
  testImplementation(project(":instrumentation:profiling:javaagent"))
  testImplementation("io.opentelemetry:opentelemetry-sdk-extension-autoconfigure")
}

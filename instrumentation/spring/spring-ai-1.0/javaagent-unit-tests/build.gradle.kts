plugins {
  id("otel.java-conventions")
}

dependencies {
  testImplementation(project(":instrumentation:spring:spring-ai-1.0:javaagent"))
  testImplementation("org.springframework.ai:spring-ai-model:1.1.2")
}

otelJava {
  minJavaVersionSupported.set(JavaVersion.VERSION_17)
}

import com.github.jengelman.gradle.plugins.shadow.tasks.ShadowJar
import net.ltgt.gradle.errorprone.errorprone
import org.gradle.api.tasks.WriteProperties
import java.util.Properties

plugins {
  `java-library`
  id("otel.java-conventions")
  id("otel.nullaway-conventions")
  id("io.opentelemetry.instrumentation.javaagent-shadowing")
}

description = "Beacon Security embedded Java agent extension"

val beaconVersion = Properties().apply {
  load(
    providers.fileContents(rootProject.layout.projectDirectory.file("beacon/version.properties"))
      .asText.get().reader()
  )
}.getProperty("version") ?: error("Missing Beacon product version")

dependencies {
  compileOnly(project(":javaagent-extension-api"))
  compileOnly(project(":instrumentation-api"))
  compileOnly(project(":instrumentation-api-incubator"))
  compileOnly("io.opentelemetry:opentelemetry-sdk-extension-autoconfigure")

  implementation("com.fasterxml.jackson.core:jackson-databind")

  testImplementation("io.opentelemetry:opentelemetry-sdk")
  testImplementation("io.opentelemetry:opentelemetry-sdk-logs")
  testImplementation("org.junit.jupiter:junit-jupiter")
  testCompileOnly("com.google.code.findbugs:jsr305")
}

tasks.withType<Jar>().configureEach {
  manifest.attributes(
    "Implementation-Title" to "Beacon Security for Java",
    "Implementation-Version" to beaconVersion,
    "Implementation-Vendor" to "Beacon Observability",
    "Beacon-Version" to beaconVersion,
  )
}

tasks.named<ShadowJar>("shadowJar") {
  archiveFileName.set("beacon-security-extension.jar")
  relocate("com.fasterxml.jackson", "io.beacon.security.shaded.jackson")
}

val generatedSecurityResources = layout.buildDirectory.dir("generated/security-resources")
val generateSecurityVersionProperties =
  tasks.register<WriteProperties>("generateSecurityVersionProperties") {
    destinationFile.set(
      generatedSecurityResources.map { it.file("META-INF/beacon/security-version.properties") }
    )
    property("version", beaconVersion)
  }

tasks.processResources {
  dependsOn(generateSecurityVersionProperties)
  from(generatedSecurityResources)
}

tasks.named("assemble") {
  dependsOn(tasks.named("shadowJar"))
}

tasks.test {
  useJUnitPlatform()
}

tasks.withType<JavaCompile>().configureEach {
  options.errorprone {
    // The migrated engine intentionally uses compact guard clauses. Keep all semantic and
    // safety checks enabled while leaving brace normalization to a dedicated readability pass.
    disable("MissingBraces")
  }
}

import com.github.jengelman.gradle.plugins.shadow.tasks.ShadowJar
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
version = beaconVersion
val securitySpec = Properties().apply {
  load(
    providers.fileContents(rootProject.layout.projectDirectory.file("beacon/security-spec.properties"))
      .asText.get().reader()
  )
}
val securitySpecRepository = securitySpec.getProperty("repository")
  ?: error("Missing Beacon Security specification repository")
val securitySpecRevision = securitySpec.getProperty("revision")
  ?: error("Missing Beacon Security specification revision")
val securitySchemaVersion = securitySpec.getProperty("schemaVersion")
  ?: error("Missing Beacon Security schema version")
val securityFingerprintVersion = securitySpec.getProperty("fingerprintVersion")
  ?: error("Missing Beacon Security fingerprint version")

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
    property("spec.repository", securitySpecRepository)
    property("spec.revision", securitySpecRevision)
    property("schema.version", securitySchemaVersion)
    property("fingerprint.version", securityFingerprintVersion)
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
  systemProperty("beacon.security.spec.schema-version", securitySchemaVersion)
  systemProperty("beacon.security.spec.fingerprint-version", securityFingerprintVersion)
}

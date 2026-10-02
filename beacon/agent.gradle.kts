/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

import groovy.json.JsonSlurper
import java.util.Properties
import java.util.zip.ZipFile
import org.gradle.jvm.tasks.Jar

// Apply only to :javaagent. Keep upstream module versions and Maven coordinates unchanged.
val beaconVersion = Properties().apply {
  load(providers.fileContents(rootProject.layout.projectDirectory.file("beacon/version.properties"))
    .asText.get().reader())
}.getProperty("version") ?: error("Missing Beacon product version")
val numeric = "(0|[1-9][0-9]*)"
require(Regex("$numeric\\.$numeric\\.$numeric(?:-(?:$numeric|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(?:\\.(?:$numeric|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*)?").matches(beaconVersion)) {
  "Invalid Beacon version: $beaconVersion (expected X.Y.Z or X.Y.Z-prerelease)"
}
val source = JsonSlurper().parseText(
  providers.fileContents(rootProject.layout.projectDirectory.file("beacon/upstream.lock.json"))
    .asText.get()
) as Map<*, *>
val upstream = source["upstream"] as Map<*, *>
val upstreamTag = upstream["releaseTag"] as? String ?: error("Missing OTel release tag")
val upstreamCommit = upstream["releaseCommit"] as? String ?: error("Missing OTel release commit")
require(Regex("v[0-9]+\\.[0-9]+\\.[0-9]+").matches(upstreamTag)) { "Invalid OTel release tag" }
require(Regex("[0-9a-f]{40}").matches(upstreamCommit)) { "Invalid OTel release commit" }
val securitySpec = Properties().apply {
  load(providers.fileContents(rootProject.layout.projectDirectory.file("beacon/security-spec.properties"))
    .asText.get().reader())
}
val securitySpecRepository = securitySpec.getProperty("repository")
  ?: error("Missing Beacon Security specification repository")
val securitySpecRevision = securitySpec.getProperty("revision")
  ?: error("Missing Beacon Security specification revision")
val securitySchemaVersion = securitySpec.getProperty("schemaVersion")
  ?: error("Missing Beacon Security schema version")
val securityFingerprintVersion = securitySpec.getProperty("fingerprintVersion")
  ?: error("Missing Beacon Security fingerprint version")
require(securitySpecRepository == "https://github.com/beacon-observability/beacon-security-spec") {
  "Unexpected Beacon Security specification repository: $securitySpecRepository"
}
require(Regex("[0-9a-f]{40}").matches(securitySpecRevision)) {
  "Invalid Beacon Security specification revision"
}
require(Regex("[1-9][0-9]*").matches(securitySchemaVersion)) {
  "Invalid Beacon Security schema version"
}
require(Regex("[1-9][0-9]*").matches(securityFingerprintVersion)) {
  "Invalid Beacon Security fingerprint version"
}

val beaconAttributes = mapOf(
  "Implementation-Title" to "Beacon Java",
  "Implementation-Version" to beaconVersion,
  "Implementation-Vendor" to "Beacon Observability",
  "Beacon-Version" to beaconVersion,
  "Beacon-Upstream-Tag" to upstreamTag,
  "Beacon-Upstream-Commit" to upstreamCommit,
  "Beacon-Instrumentation-Version" to project.version.toString(),
  "Beacon-Security-Spec-Commit" to securitySpecRevision,
  "Beacon-Security-Schema-Version" to securitySchemaVersion,
  "Beacon-Security-Fingerprint-Version" to securityFingerprintVersion,
)
val beaconFileName = "beacon-javaagent-$beaconVersion.jar"
val beaconSecurityProject = rootProject.findProject(":extensions:security")
val beaconSecurityExtension = beaconSecurityProject?.let {
  configurations.create("beaconSecurityExtension") {
    isCanBeResolved = true
    isCanBeConsumed = false
  }.also { configuration ->
    dependencies.add(
      configuration.name,
      dependencies.project(
        mapOf(
          "path" to it.path,
          "configuration" to "shadowRuntimeElements",
        )
      )
    )
  }
}
val beaconSecurityDependencies = beaconSecurityProject?.let {
  configurations.create("beaconSecurityDependencies") {
    isCanBeResolved = true
    isCanBeConsumed = false
  }.also { configuration ->
    dependencies.add(configuration.name, dependencies.project(mapOf("path" to it.path)))
  }
}
val beaconAgent = tasks.named<Jar>("shadowJar") {
  // Explicit file name prevents upstream archive conventions from adding an OTel prefix.
  archiveFileName.set(beaconFileName)
  manifest.attributes(beaconAttributes)
  from(rootProject.layout.projectDirectory.file("beacon/upstream.lock.json")) {
    into("META-INF/beacon")
  }
  from(rootProject.layout.projectDirectory.file("beacon/version.properties")) {
    into("META-INF/beacon")
  }
  from(rootProject.layout.projectDirectory.file("beacon/security-spec.properties")) {
    into("META-INF/beacon")
  }
  if (beaconSecurityExtension != null) {
    from(beaconSecurityExtension) {
      into("extensions")
      rename { "beacon-security-extension.jar" }
    }
  }
}

val verifyBeaconAgent = tasks.register("verifyBeaconAgent") {
  group = "verification"
  description = "Verify Beacon agent name, product identity and upstream provenance."
  inputs.file(beaconAgent.flatMap { it.archiveFile })
  inputs.property("expectedFileName", beaconFileName)
  inputs.property("expectsSecurityExtension", beaconSecurityProject != null)
  beaconAttributes.forEach { (key, value) -> inputs.property("manifest.$key", value) }
  doLast {
    val agentFile = inputs.files.singleFile
    val expectedFileName = inputs.properties.getValue("expectedFileName") as String
    check(agentFile.name == expectedFileName) { "Unexpected Beacon artifact: ${agentFile.name}" }
    ZipFile(agentFile).use { zip ->
      val manifest = zip.getInputStream(zip.getEntry("META-INF/MANIFEST.MF")).use {
        java.util.jar.Manifest(it).mainAttributes
      }
      val expectedAttributes = inputs.properties
        .filterKeys { it.startsWith("manifest.") }
        .mapKeys { it.key.removePrefix("manifest.") }
      for ((key, value) in expectedAttributes) {
        check(manifest.getValue(key) == value) { "Incorrect agent manifest attribute: $key" }
      }
      check(manifest.getValue("Premain-Class") == "io.opentelemetry.javaagent.OpenTelemetryAgent") {
        "Missing original Java agent entry point"
      }
      check(zip.getEntry("META-INF/beacon/upstream.lock.json") != null)
      check(zip.getEntry("META-INF/beacon/version.properties") != null)
      check(zip.getEntry("META-INF/beacon/security-spec.properties") != null)
      if (inputs.properties.getValue("expectsSecurityExtension") as Boolean) {
        check(zip.getEntry("extensions/beacon-security-extension.jar") != null) {
          "Missing embedded Beacon Security extension"
        }
      }
    }
  }
}
tasks.named("assemble") { dependsOn(verifyBeaconAgent) }
tasks.named("check") { dependsOn(verifyBeaconAgent) }

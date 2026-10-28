// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

import org.gradle.api.tasks.testing.Test

val partition = providers.gradleProperty("testPartition").orNull?.toIntOrNull()
  ?: throw GradleException("Test partition must be specified as an integer")
require(partition in 0..3) { "Invalid test partition: $partition" }

val listTests = tasks.register("listBeaconTestsInPartition") {
  group = "Help"
  description = "List a Beacon test partition without resolving the check task graph"
}

// Wait for all plugins and afterEvaluate callbacks, then realize Test tasks directly. Merely
// registering configureEach callbacks would miss tasks not realized by the requested task graph.
gradle.projectsEvaluated {
  val discovered = mutableListOf<String>()
  var index = 0
  // The project configuration action acquires each project's state lock. Test configuration
  // may resolve project-local providers and must not run under the root project's lock.
  rootProject.subprojects {
    if (index++ % 4 == partition) {
      discovered.addAll(tasks.withType<Test>().map { it.path })
    }
  }
  val testTasks = discovered.filterNot { it == ":smoke-tests:test" || it == ":instrumentation:test" }.sorted()
  check(testTasks.isNotEmpty()) { "Test partition $partition is empty" }
  val output = rootProject.layout.projectDirectory.file("test-tasks.txt")
  listTests.configure {
    inputs.property("partition", partition)
    inputs.property("testTasks", testTasks)
    outputs.file(output)
    doLast {
      output.asFile.writeText(testTasks.joinToString("\n", postfix = "\n"))
    }
  }
}

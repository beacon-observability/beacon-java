// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

import org.gradle.api.plugins.jvm.JvmTestSuite
import org.gradle.api.tasks.testing.Test
import org.gradle.testing.base.TestingExtension

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
      val suites = extensions.findByType<TestingExtension>()?.suites?.withType<JvmTestSuite>()
      val suiteTests = suites?.flatMap { suite -> suite.targets.map { it.testTask.get() } }?.toSet().orEmpty()
      val selectedTests = mutableSetOf<Test>()
      val visited = mutableSetOf<Task>()
      fun visit(task: Task) {
        if (!visited.add(task)) {
          return
        }
        if (task is Test) {
          selectedTests.add(task)
          return
        }
        // Lifecycle aggregators have no actions. Quality/build tasks can have expensive
        // implicit input dependencies; those are not test-suite selectors.
        if (task.actions.isEmpty()) {
          rootProject.project(task.project.path) {
            task.taskDependencies.getDependencies(task).forEach(::visit)
          }
        }
      }
      tasks.findByName("check")?.let(::visit)
      // Suites can be intentionally excluded from check for the current dependency/JDK mode.
      // Follow lifecycle aggregators and stop at executable tasks, avoiding input graphs.
      discovered.addAll(tasks.withType<Test>().filter { it !in suiteTests || it in selectedTests }.map { it.path })
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

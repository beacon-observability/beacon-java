// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

const assert = require('node:assert/strict');
const { mkdtempSync, writeFileSync, readFileSync, mkdirSync, rmSync, copyFileSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { resolve } = require('node:path');
const { spawnSync } = require('node:child_process');
const { test } = require('node:test');
const { verify } = require('./verify-test-partitions.cjs');

const root = resolve(__dirname, '../..');

test('suite discovery honors dependency and JDK mode through lifecycle aggregators', (t) => {
  const fixture = mkdtempSync(resolve(tmpdir(), 'beacon-suite-selection-'));
  t.after(() => rmSync(fixture, { recursive: true, force: true }));
  writeFileSync(resolve(fixture, 'settings.gradle.kts'), 'include(":a", ":b", ":c", ":d")\n');
  copyFileSync(resolve(root, 'beacon/testing/test-partitions.gradle.kts'),
    resolve(fixture, 'partitions.gradle.kts'));
  writeFileSync(resolve(fixture, 'build.gradle.kts'), 'apply(from = "partitions.gradle.kts")\n');
  for (const name of ['a', 'b', 'c', 'd']) {
    mkdirSync(resolve(fixture, name));
    writeFileSync(resolve(fixture, name, 'build.gradle.kts'), `
plugins { java }
testing.suites {
  register<JvmTestSuite>("baselineTest")
  register<JvmTestSuite>("latestTest")
  register<JvmTestSuite>("modernTest")
}
val selectedSuites = tasks.register("selectedSuites") {
  val latest = providers.gradleProperty("testLatestDeps").orNull == "true"
  val modern = providers.gradleProperty("testJavaVersion").orNull?.toInt() == 17
  if (latest) {
    if (modern) dependsOn(testing.suites.named("latestTest"))
  } else {
    dependsOn(testing.suites.named("baselineTest"))
  }
  if (modern) dependsOn(testing.suites.named("modernTest"))
}
val unrelatedQualityCheck = tasks.register("unrelatedQualityCheck") {
  dependsOn(tasks.compileTestJava)
  doLast { throw GradleException("Discovery must not execute quality checks") }
}
tasks.check { dependsOn(selectedSuites, unrelatedQualityCheck) }
repositories { mavenCentral() }
dependencies { testImplementation("invalid.example:must-not-resolve:0") }
tasks.withType<Test>().configureEach {
  doFirst { throw GradleException("Discovery must not execute tests") }
}
`);
  }
  for (const [java, latest, expected] of [
    [8, false, ['baselineTest', 'test']],
    [17, false, ['baselineTest', 'modernTest', 'test']],
    [8, true, ['test']],
    [17, true, ['latestTest', 'modernTest', 'test']],
  ]) {
    const result = spawnSync(resolve(root, 'gradlew'), [
      '-p', fixture, 'listBeaconTestsInPartition', '-PtestPartition=0',
      `-PtestJavaVersion=${java}`, `-PtestLatestDeps=${latest}`,
      '--offline', '--configuration-cache', '--console=plain', '--max-workers=2',
    ], { encoding: 'utf8', timeout: 0, maxBuffer: 4 * 1024 * 1024 });
    assert.equal(result.status, 0, result.stdout + result.stderr);
    assert.deepEqual(readFileSync(resolve(fixture, 'test-tasks.txt'), 'utf8').trim().split('\n'),
      expected.map((task) => `:a:${task}`));
  }
});

test('coverage comparison rejects omissions, moves, duplicates and unexpected tasks', () => {
  const baseline = { 0: [':a:test'], 1: [':b:test'], 2: [':c:test'], 3: [':d:test'] };
  const optimized = Object.values(baseline).map((tasks) => [...tasks]);
  assert.equal(verify(baseline, baseline[0], optimized).baseline_tasks, 4);
  optimized[0].push(':a:lateTest');
  assert.throws(() => verify(baseline, baseline[0], optimized), /Unexpected partition/);
  optimized[0].pop();
  assert.throws(() => verify(baseline, [':wrong:test'], optimized));
  const missing = structuredClone(optimized);
  missing[1] = [':other:test'];
  assert.throws(() => verify(baseline, baseline[0], missing), /Missing partition/);
  const duplicate = structuredClone(optimized);
  duplicate[1].push(':a:test');
  assert.throws(() => verify(baseline, baseline[0], duplicate), /Duplicate test task/);
});

test('partition discovery includes late and custom tests without resolving or executing them', (t) => {
  const fixture = mkdtempSync(resolve(tmpdir(), 'beacon-test-partitions-'));
  t.after(() => rmSync(fixture, { recursive: true, force: true }));
  const modules = ['a', 'b', 'c', 'd', 'instrumentation', 'smoke-tests'];
  writeFileSync(resolve(fixture, 'settings.gradle.kts'),
    `rootProject.name = "partition-fixture"\ninclude(${modules.map((name) => `":${name}"`).join(', ')})\n`);
  copyFileSync(resolve(root, 'beacon/testing/test-partitions.gradle.kts'),
    resolve(fixture, 'partitions.gradle.kts'));
  writeFileSync(resolve(fixture, 'build.gradle.kts'), 'apply(from = "partitions.gradle.kts")\n');
  for (const name of modules) {
    mkdirSync(resolve(fixture, name));
    writeFileSync(resolve(fixture, name, 'build.gradle.kts'), `
plugins { java }
repositories { mavenCentral() }
dependencies { testImplementation("invalid.example:must-not-resolve:0") }
tasks.register<Test>("detachedTest")
afterEvaluate { tasks.register<Test>("lateTest") }
tasks.check { dependsOn("detachedTest", "lateTest") }
tasks.withType<Test>().configureEach {
  doFirst { throw GradleException("Discovery must not execute tests") }
}
`);
  }
  const collected = new Set();
  const partitions = [];
  for (let partition = 0; partition < 4; partition += 1) {
    const result = spawnSync(resolve(root, 'gradlew'), [
      '-p', fixture, 'listBeaconTestsInPartition', `-PtestPartition=${partition}`,
      '--offline', '--no-configuration-cache', '--console=plain', '--max-workers=2',
    ], { encoding: 'utf8', timeout: 0, maxBuffer: 4 * 1024 * 1024 });
    assert.equal(result.status, 0, result.stdout + result.stderr);
    assert.doesNotMatch(result.stdout, /> Task :[^\s]+:(compile|test|lateTest|detachedTest)/);
    const tasks = readFileSync(resolve(fixture, 'test-tasks.txt'), 'utf8').trim().split('\n');
    partitions.push(tasks);
    const expected = modules.filter((_, index) => index % 4 === partition)
      .flatMap((name) => ['test', 'lateTest', 'detachedTest'].map((task) => `:${name}:${task}`))
      .filter((task) => task !== ':smoke-tests:test' && task !== ':instrumentation:test').sort();
    assert.deepEqual(tasks, expected);
    for (const task of tasks) {
      assert(!collected.has(task), `Task duplicated across partitions: ${task}`);
      collected.add(task);
    }
  }
  assert.equal(collected.size, 16);
  for (let attempt = 0; attempt < 2; attempt += 1) {
    const cached = spawnSync(resolve(root, 'gradlew'), [
      '-p', fixture, 'listBeaconTestsInPartition', '-PtestPartition=0',
      '--offline', '--configuration-cache', '--console=plain', '--max-workers=2',
    ], { encoding: 'utf8', timeout: 0, maxBuffer: 4 * 1024 * 1024 });
    assert.equal(cached.status, 0, cached.stdout + cached.stderr);
    if (attempt === 1) assert.match(cached.stdout, /Reusing configuration cache/);
  }
  const invalid = spawnSync(resolve(root, 'gradlew'), [
    '-p', fixture, 'listBeaconTestsInPartition', '-PtestPartition=4',
    '--offline', '--no-configuration-cache', '--console=plain',
  ], { encoding: 'utf8', timeout: 0 });
  assert.notEqual(invalid.status, 0);
  assert.match(invalid.stdout + invalid.stderr, /Invalid test partition/);

  // Exercise the independent observer with the actual legacy implementation. Remove the
  // deliberately unresolvable dependency before building its complete check graph.
  for (const name of modules) {
    const file = resolve(fixture, name, 'build.gradle.kts');
    writeFileSync(file, readFileSync(file, 'utf8').replace(
      'dependencies { testImplementation("invalid.example:must-not-resolve:0") }', '',
    ));
  }
  const source = readFileSync(resolve(root, 'build.gradle.kts'), 'utf8');
  const start = source.indexOf('if (gradle.startParameter.taskNames.contains("listTestsInPartition"))');
  const end = source.indexOf('\ntasks {', start);
  assert(start >= 0 && end > start);
  writeFileSync(resolve(fixture, 'build.gradle.kts'),
    'tasks.register("check") { dependsOn(subprojects.map { "${it.path}:check" }) }\n'
      + source.slice(start, end));
  const legacy = spawnSync(resolve(root, 'gradlew'), [
    '-p', fixture, 'check', 'listTestsInPartition', '-PtestPartition=0',
    '-I', resolve(root, 'beacon/testing/record-test-partitions.init.gradle'),
    '--offline', '--no-configuration-cache', '--console=plain', '--max-workers=2',
  ], { cwd: fixture, encoding: 'utf8', timeout: 0, maxBuffer: 4 * 1024 * 1024 });
  assert.equal(legacy.status, 0, legacy.stdout + legacy.stderr);
  const baseline = JSON.parse(readFileSync(resolve(fixture, 'build/beacon-ci/legacy-test-partitions.json'), 'utf8'));
  const previous = readFileSync(resolve(fixture, 'test-tasks.txt'), 'utf8').trim().split('\n');
  const report = verify(baseline, previous, partitions);
  assert.equal(report.baseline_tasks, 16);
  assert.equal(report.optimized_tasks, 16);
  assert.equal(report.added_tasks.length, 0);
});

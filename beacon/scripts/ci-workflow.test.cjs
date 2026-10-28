// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

const assert = require('node:assert/strict');
const { readFileSync, readdirSync, statSync } = require('node:fs');
const { resolve } = require('node:path');
const { spawnSync } = require('node:child_process');
const { test } = require('node:test');

const root = resolve(__dirname, '../..');
const workflows = resolve(root, '.github/workflows');
const source = readFileSync(resolve(workflows, 'beacon-ci.yml'), 'utf8');
const gate = source.match(/          node <<'NODE'\n([\s\S]*?)          NODE/)[1]
  .replace(/^          /gm, '');

function actionSteps(action) {
  const escaped = action.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return [...source.matchAll(
    new RegExp(`(^      - uses: ${escaped}[^\\n]*\\n(?:(?!^      - ).*(?:\\n|$))*)`, 'gm'),
  )].map((match) => match[1]);
}

function results(muzzle = false, full = false) {
  return {
    plan: { result: 'success', outputs: { muzzle: String(muzzle), full: String(full), partition_check: 'false' } },
    build: { result: 'success' }, quality: { result: 'success' }, tests: { result: 'success' },
    muzzle: { result: muzzle ? 'success' : 'skipped' },
    'latest-deps': { result: full ? 'success' : 'skipped' },
    'upstream-smoke': { result: full ? 'success' : 'skipped' },
    native: { result: 'skipped' },
    'partition-check': { result: 'skipped' },
  };
}

function check(needs, native = false, lightweight = false) {
  return spawnSync(process.execPath, ['-e', gate], {
    env: {
      ...process.env,
      NEEDS_JSON: JSON.stringify(needs),
      NATIVE: String(native),
      LIGHTWEIGHT: String(lightweight),
    },
    encoding: 'utf8',
  });
}

test('upstream build and PR image entry jobs stay isolated', () => {
  const files = ['build.yml', 'build-pull-request.yml',
    ...readdirSync(workflows).filter((file) => /^pr-smoke-test-.*\.yml$/.test(file))];
  for (const file of files) {
    const jobs = readFileSync(resolve(workflows, file), 'utf8').split('\njobs:\n')[1];
    const blocks = jobs.split(/(?=^  [\w-]+:\n)/m).filter((block) => /^  [\w-]+:\n/.test(block));
    assert(blocks.length > 0, file);
    for (const block of blocks) {
      assert.match(block, /^    if: github.repository == 'open-telemetry\/opentelemetry-java-instrumentation'/m, file);
    }
  }
});

test('all core and optional jobs are represented in the final gate', () => {
  assert.match(source, /needs: \[plan, build, quality, partition-check, tests, muzzle, latest-deps, native, upstream-smoke\]/);
  assert.match(source, /if: github.repository == 'beacon-observability\/beacon-java'/);
  assert.match(source, /if: \$\{\{ always\(\) && github.repository == 'beacon-observability\/beacon-java' \}\}/);
  assert.doesNotMatch(source, /GuanceCloud\/beacon-java/);
  assert(!source.includes('continue-on-error:'), 'Failures must not be ignored');
  assert(!source.includes('pull_request_target:'), 'PR code must not run with privileged context');
});

test('only artifact-producing build disables dependency caches', () => {
  const setupNodeSteps = actionSteps('actions/setup-node@');
  assert.equal(setupNodeSteps.length, 4);
  for (const step of setupNodeSteps) {
    assert.match(step, /^          cache: ''$/m);
    assert.match(step, /^          package-manager-cache: false$/m);
  }

  const setupGradleSteps = actionSteps('gradle/actions/setup-gradle@');
  assert.equal(setupGradleSteps.length, 5);
  assert.equal(setupGradleSteps.filter((step) => /^          cache-disabled: true$/m.test(step)).length, 1);
  assert.equal(setupGradleSteps.filter((step) => /^          cache-read-only: true$/m.test(step)).length, 4);
});

test('the packaged-agent path includes embedded Security acceptance', () => {
  assert.match(source, /-p beacon\/testing\/security-smoke-fixture shadowJar --no-build-cache/);
  assert.match(source, /node beacon\/scripts\/security-smoke\.cjs "\$agent"/);
});

test('main pushes use the lightweight build and smoke-test path', () => {
  assert.match(source, /LIGHTWEIGHT:.*github\.event_name == 'push'.*refs\/heads\/main/);
  assert.equal(
    (source.match(/github\.event_name != 'push' \|\| github\.ref != 'refs\/heads\/main'/g) || []).length,
    6,
    'quality, partition verification, tests, Muzzle, latest-deps and upstream smoke must skip on main pushes',
  );
  assert.match(source, /max-parallel: 16/);
  const needs = results(true, true);
  needs.quality.result = 'skipped';
  needs.tests.result = 'skipped';
  needs.muzzle.result = 'skipped';
  needs['latest-deps'].result = 'skipped';
  needs['upstream-smoke'].result = 'skipped';
  assert.equal(check(needs, false, true).status, 0);

  for (const job of ['plan', 'build']) {
    const failed = structuredClone(needs);
    failed[job].result = 'failure';
    assert.equal(check(failed, false, true).status, 1, job);
  }
});

test('ordinary, upgrade and full successes pass with unselected jobs skipped', () => {
  for (const needs of [results(), results(true), results(true, true)]) {
    assert.equal(check(needs).status, 0);
  }
});

test('failed, cancelled or skipped core jobs fail closed', () => {
  for (const job of ['plan', 'build', 'quality', 'tests']) {
    for (const state of ['failure', 'cancelled', 'skipped']) {
      const needs = results();
      needs[job].result = state;
      assert.equal(check(needs).status, 1, `${job}: ${state}`);
    }
  }
});

test('selected Muzzle and full-profile jobs cannot silently skip', () => {
  for (const job of ['muzzle', 'latest-deps', 'upstream-smoke']) {
    for (const state of ['failure', 'cancelled', 'skipped']) {
      const needs = results(true, true);
      needs[job].result = state;
      assert.equal(check(needs).status, 1, `${job}: ${state}`);
    }
  }
});

test('requested native tests must succeed', () => {
  const needs = results();
  assert.equal(check(needs, true).status, 1);
  needs.native.result = 'success';
  assert.equal(check(needs, true).status, 0);
});


test('Beacon CI references executable repository scripts', () => {
  const scripts = [...source.matchAll(/(?:^\s*|run:\s*)(\.github\/scripts\/[\w.-]+\.sh)(?=\s|$)/gm)]
    .map((match) => match[1]);
  assert(scripts.length > 0, 'Expected repository script checks in Beacon CI');
  for (const script of scripts) {
    const info = statSync(resolve(root, script));
    assert(info.isFile(), `${script} must exist after an upstream upgrade`);
    assert(info.mode & 0o111, `${script} must be executable`);
  }
});

test('same-repository reusable workflows use pinned self-repository references', () => {
  for (const file of readdirSync(workflows).filter((name) => /\.ya?ml$/.test(name))) {
    const contents = readFileSync(resolve(workflows, file), 'utf8');
    for (const match of contents.matchAll(/^    uses: ([.$]\/\.github\/workflows\/[^\s]+)$/gm)) {
      const reference = match[1];
      assert(reference.startsWith('$/'), `${file}: use the self-repository syntax`);
      assert(!reference.includes('@'), `${file}: local references use the caller commit`);
      assert(statSync(resolve(root, reference.slice(2))).isFile(), `${file}: missing workflow`);
    }
  }
});

test('test partitions avoid the check graph and keep full diagnostics in reports', () => {
  assert.match(source, /\.\/gradlew listBeaconTestsInPartition "-PtestPartition=\$TEST_PARTITION"/);
  assert.match(source, /-I beacon\/testing\/record-test-partitions\.init\.gradle --no-configuration-cache/);
  assert.match(source, /-PtestShowStandardStreams=false/);
  const tests = source.split('\n  tests:\n')[1].split('\n  muzzle:\n')[0];
  assert.doesNotMatch(tests, /check -x spotlessCheck listTestsInPartition/);
  const latest = readFileSync(resolve(workflows, 'reusable-test-latest-deps.yml'), 'utf8');
  assert.match(latest, /listBeaconTestsInPartition/);
  assert.doesNotMatch(latest, /check -x spotlessCheck/);
  const convention = readFileSync(resolve(root, 'conventions/src/main/kotlin/otel.java-conventions.gradle.kts'), 'utf8');
  assert.match(convention, /showStandardStreams = otelProps\.testShowStandardStreams/);
  assert.match(convention, /junitXml\.isOutputPerTestCase = true/);
});

test('selected partition verification cannot fail or silently skip', () => {
  for (const result of ['failure', 'cancelled', 'skipped']) {
    const needs = results();
    needs.plan.outputs.partition_check = 'true';
    needs['partition-check'].result = result;
    assert.equal(check(needs).status, 1, result);
  }
  const needs = results();
  needs.plan.outputs.partition_check = 'true';
  needs['partition-check'].result = 'success';
  assert.equal(check(needs).status, 0);
});

test('only trusted main refreshes the test cache without uploading runtime artifacts', () => {
  const warm = readFileSync(resolve(workflows, 'beacon-test-cache.yml'), 'utf8');
  assert.match(warm, /branches: \[main\]/);
  assert.match(warm, /github\.repository == 'beacon-observability\/beacon-java' && github\.ref == 'refs\/heads\/main'/);
  assert.match(warm, /cache-read-only: false/);
  assert.match(warm, /-PtestLatestDeps=true/);
  assert.doesNotMatch(warm, /pull_request|upload-artifact|:javaagent:assemble|contents: write/);
});

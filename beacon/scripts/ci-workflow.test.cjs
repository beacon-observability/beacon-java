// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

const assert = require('node:assert/strict');
const { readFileSync, readdirSync } = require('node:fs');
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
    plan: { result: 'success', outputs: { muzzle: String(muzzle), full: String(full) } },
    build: { result: 'success' }, quality: { result: 'success' }, tests: { result: 'success' },
    muzzle: { result: muzzle ? 'success' : 'skipped' },
    'latest-deps': { result: full ? 'success' : 'skipped' },
    'upstream-smoke': { result: full ? 'success' : 'skipped' },
    native: { result: 'skipped' },
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
  assert.match(source, /needs: \[plan, build, quality, tests, muzzle, latest-deps, native, upstream-smoke\]/);
  assert.match(source, /if: github.repository == 'beacon-observability\/beacon-java'/);
  assert.match(source, /if: \$\{\{ always\(\) && github.repository == 'beacon-observability\/beacon-java' \}\}/);
  assert.doesNotMatch(source, /GuanceCloud\/beacon-java/);
  assert(!source.includes('continue-on-error:'), 'Failures must not be ignored');
  assert(!source.includes('pull_request_target:'), 'PR code must not run with privileged context');
});

test('only artifact-producing build disables dependency caches', () => {
  const setupNodeSteps = actionSteps('actions/setup-node@');
  assert.equal(setupNodeSteps.length, 3);
  for (const step of setupNodeSteps) {
    assert.match(step, /^          cache: ''$/m);
    assert.match(step, /^          package-manager-cache: false$/m);
  }

  const setupGradleSteps = actionSteps('gradle/actions/setup-gradle@');
  assert.equal(setupGradleSteps.length, 4);
  assert.equal(setupGradleSteps.filter((step) => /^          cache-disabled: true$/m.test(step)).length, 1);
  assert.equal(setupGradleSteps.filter((step) => /^          cache-read-only: true$/m.test(step)).length, 3);
});

test('main pushes use the lightweight build and smoke-test path', () => {
  assert.match(source, /LIGHTWEIGHT:.*github\.event_name == 'push'.*refs\/heads\/main/);
  assert.equal(
    (source.match(/github\.event_name != 'push' \|\| github\.ref != 'refs\/heads\/main'/g) || []).length,
    5,
    'quality, tests, Muzzle, latest-deps and upstream smoke must skip on main pushes',
  );
  assert.match(source, /max-parallel: 8/);
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

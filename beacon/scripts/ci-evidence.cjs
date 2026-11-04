// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// CI produces one immutable candidate. Consumers verify GitHub's run/job metadata,
// the checked-out Git tree and every payload digest before promoting any bytes.
const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const { createHash } = require('node:crypto');
const { appendFileSync, copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join, resolve } = require('node:path');
const { plan } = require('./ci-plan.cjs');
const { assertReleaseVersion, productVersion, verifyArtifact, verifySbom } = require('./release-metadata.cjs');

const repository = 'beacon-observability/beacon-java';
const shaPattern = /^[0-9a-f]{40}$/;
const digestPattern = /^[0-9a-f]{64}$/;
const git = (...args) => execFileSync('git', args, { encoding: 'utf8' }).trim();
const digest = (file) => createHash('sha256').update(readFileSync(file)).digest('hex');
const payloads = (version) => [
  `beacon-javaagent-${version}.jar`, `beacon-javaagent-${version}.spdx.json`,
  'LICENSE', 'THIRD_PARTY_LICENSES.md', 'verification/security-smoke-fixture.jar',
];

function stage(directory, selectedPlan, env = process.env) {
  const version = productVersion();
  assertReleaseVersion(version.replace(/-SNAPSHOT$/, ''));
  const sourceCommit = git('rev-parse', 'HEAD');
  git('diff', '--exit-code', 'HEAD', '--');
  assert.equal(sourceCommit, env.GITHUB_SHA, 'Build checkout differs from workflow source');
  const files = payloads(version);
  const sources = [
    `javaagent/build/libs/${files[0]}`, 'javaagent/build/spdx/beacon-javaagent.spdx.json',
    'LICENSE', 'licenses/licenses.md',
    'beacon/testing/security-smoke-fixture/build/libs/beacon-security-smoke-fixture.jar',
  ];
  mkdirSync(join(directory, 'verification'), { recursive: true });
  sources.forEach((source, index) => copyFileSync(source, join(directory, files[index])));
  // assemble already verifies product identity for development SNAPSHOTs too.
  // Release verification additionally requires a stable/RC version and source-bound SBOM.
  if (!version.endsWith('-SNAPSHOT')) {
    verifyArtifact(join(directory, files[0]), version);
    verifySbom(join(directory, files[1]), version, sourceCommit);
  }
  const evidence = {
    schema_version: 1, repository, run_id: Number(env.GITHUB_RUN_ID),
    run_attempt: Number(env.GITHUB_RUN_ATTEMPT), source_commit: sourceCommit,
    source_tree: git('rev-parse', 'HEAD^{tree}'), version, plan: selectedPlan,
    candidate_artifact: `beacon-javaagent-${env.GITHUB_RUN_ATTEMPT}`,
    sha256: Object.fromEntries(files.map((file) => [file, digest(join(directory, file))])),
  };
  writeFileSync(join(directory, 'ci-evidence.json'), JSON.stringify(evidence, null, 2) + '\n');
  return evidence;
}

function verifyValidation(run, jobs, evidence, expectedTree, commit) {
  assert(Number.isSafeInteger(run.id) && run.id > 0, 'Invalid GitHub run ID');
  assert.equal(run.path, '.github/workflows/beacon-ci.yml', 'Wrong CI workflow');
  assert.equal(run.repository.full_name, repository, 'Wrong validation repository');
  assert.equal(run.head_repository.full_name, repository, 'Fork artifacts cannot be promoted');
  assert(['pull_request', 'workflow_dispatch'].includes(run.event), 'A PR or manual validation is required');
  assert.equal(run.status, 'completed', 'Validation is not complete');
  assert.equal(run.conclusion, 'success', 'Validation did not succeed');
  assert.equal(evidence.schema_version, 1, 'Unsupported CI evidence');
  assert.equal(evidence.repository, repository);
  assert.equal(evidence.run_id, run.id, 'Evidence belongs to a different run');
  assert(Number.isSafeInteger(evidence.run_attempt) && evidence.run_attempt > 0
    && evidence.run_attempt <= run.run_attempt, 'Invalid evidence attempt');
  assert.match(evidence.source_commit, shaPattern);
  assert.match(expectedTree, shaPattern);
  assert.equal(evidence.source_tree, expectedTree, 'Validated tree differs from release source');
  assert.equal(commit.sha, evidence.source_commit, 'Wrong build commit');
  assert.equal(commit.tree.sha, expectedTree, 'Build commit has different content');
  if (run.event === 'pull_request') {
    assert(evidence.source_commit === run.head_sha
      || (commit.parents.length === 2 && commit.parents[1].sha === run.head_sha),
    'Build source is not the PR head or its test merge');
  } else {
    assert.equal(evidence.source_commit, run.head_sha, 'Manual checkout differs from run source');
  }

  const selected = evidence.plan;
  assert(['pr', 'upgrade', 'full'].includes(selected.profile), 'Invalid validation profile');
  const expected = plan([], selected.profile === 'full', selected.profile === 'upgrade');
  assert.deepEqual(selected.matrix, expected.matrix, 'Unexpected validation matrix');
  assert.equal(selected.full, expected.full);
  assert.equal(typeof selected.muzzle, 'boolean');
  assert.equal(typeof selected.partition_check, 'boolean');
  if (selected.profile !== 'pr') assert.equal(selected.muzzle, true);
  if (selected.full) assert.equal(selected.partition_check, true);
  const requireSuccess = (name) => {
    const matches = jobs.filter((job) => job.name === name);
    assert.equal(matches.length, 1, `Missing or duplicate CI job: ${name}`);
    assert.equal(matches[0].conclusion, 'success', `${name} did not succeed`);
    return matches[0];
  };
  requireSuccess('Beacon required');
  const build = requireSuccess('build');
  assert.equal(build.run_attempt, evidence.run_attempt, 'Evidence does not belong to the successful build');
  requireSuccess('quality');
  const testNames = selected.matrix.include.map(({ java, indy, partition }) =>
    `tests (JDK ${java}, indy ${indy}, part ${partition})`);
  assert.deepEqual(jobs.filter((job) => job.name.startsWith('tests (JDK ')).map((job) => job.name).sort(),
    [...testNames].sort(), 'Incomplete or duplicate test matrix');
  testNames.forEach(requireSuccess);
  if (selected.partition_check) requireSuccess('Verify test partition coverage');
  if (selected.muzzle) {
    for (let part = 1; part <= 4; part += 1) requireSuccess(`muzzle / muzzle (:instrumentation:muzzle${part})`);
  }
  if (selected.full) {
    requireSuccess('upstream-smoke');
    for (let part = 0; part < 4; part += 1) requireSuccess(`latest-deps / testLatestDeps${part}`);
  }
  assert.equal(evidence.candidate_artifact, `beacon-javaagent-${evidence.run_attempt}`);
  assertReleaseVersion(evidence.version.replace(/-SNAPSHOT$/, ''));
  const files = payloads(evidence.version);
  assert.deepEqual(Object.keys(evidence.sha256).sort(), files.sort(), 'Incomplete candidate inventory');
  Object.values(evidence.sha256).forEach((value) => assert.match(value, digestPattern));
}

function verifyPayload(directory, evidence, version) {
  assert.equal(evidence.version, version, 'Candidate version differs from source');
  for (const file of payloads(version)) {
    assert.equal(digest(join(directory, file)), evidence.sha256[file], `Candidate digest changed: ${file}`);
  }
  verifyArtifact(join(directory, `beacon-javaagent-${version}.jar`), version);
  verifySbom(join(directory, `beacon-javaagent-${version}.spdx.json`), version, evidence.source_commit);
}

// Small pages avoid the GitHub job-list 502 seen with 100-item pages. Retry
// transient network/server/rate-limit responses, but never hide a final error.
function api(path, binary = false) {
  for (let attempt = 0; ; attempt += 1) {
    try {
      const result = execFileSync('gh', ['api', `repos/${repository}/${path}`], {
        encoding: binary ? undefined : 'utf8', maxBuffer: 128 * 1024 * 1024, timeout: 60_000,
        stdio: ['ignore', 'pipe', 'pipe'],
      });
      return binary ? result : JSON.parse(result);
    } catch (error) {
      const message = String(error.stderr || error.message);
      if (attempt === 2 || !/HTTP (429|5\d\d)|timeout|ETIMEDOUT|TLS|connection|EOF/i.test(message)) throw error;
      console.error(`GitHub API retry ${attempt + 1}: ${path}`);
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 1000 * (attempt + 1));
    }
  }
}

function pages(path, key, request = api) {
  const result = [];
  for (let page = 1; ; page += 1) {
    const value = request(`${path}${path.includes('?') ? '&' : '?'}per_page=30&page=${page}`);
    const items = value[key];
    assert(Array.isArray(items), `Missing API collection: ${key}`);
    result.push(...items);
    if (items.length < 30) return result;
  }
}

function readEvidence(artifact, directory, request = api) {
  assert(Number.isSafeInteger(artifact.id) && artifact.id > 0);
  const archive = join(directory, 'evidence.zip');
  writeFileSync(archive, request(`actions/artifacts/${artifact.id}/zip`, true));
  return JSON.parse(execFileSync('unzip', ['-p', archive, 'ci-evidence.json'], {
    encoding: 'utf8', maxBuffer: 1024 * 1024,
  }));
}

function resolveValidation(run, tree, directory, request = api) {
  if (run.path !== '.github/workflows/beacon-ci.yml' || run.repository?.full_name !== repository
    || run.status !== 'completed' || run.conclusion !== 'success'
    || !['pull_request', 'workflow_dispatch'].includes(run.event)
    || run.head_repository?.full_name !== repository) return null;
  const artifacts = pages(`actions/runs/${run.id}/artifacts`, 'artifacts', request);
  const manifests = artifacts.filter((item) => /^beacon-ci-evidence-[1-9][0-9]*$/.test(item.name) && !item.expired)
    .sort((a, b) => Number(b.name.split('-').at(-1)) - Number(a.name.split('-').at(-1)));
  for (const manifest of manifests) {
    const evidence = readEvidence(manifest, directory, request);
    if (evidence.source_tree !== tree) continue;
    assert.equal(manifest.name, `beacon-ci-evidence-${evidence.run_attempt}`);
    const candidate = artifacts.find((item) => item.name === evidence.candidate_artifact && !item.expired);
    if (!candidate) continue;
    assert.match(evidence.source_commit, shaPattern);
    const commit = request(`git/commits/${evidence.source_commit}`);
    const jobs = pages(`actions/runs/${run.id}/jobs?filter=latest`, 'jobs', request);
    if (jobs.find((job) => job.name === 'build')?.run_attempt !== evidence.run_attempt) continue;
    verifyValidation(run, jobs, evidence, tree, commit);
    return { run, evidence, artifact_id: candidate.id };
  }
  return null;
}

function findValidation(tree, directory, runId, request = api) {
  if (runId) {
    assert.match(runId, /^[1-9][0-9]*$/, 'Invalid validation run ID');
    const result = resolveValidation(request(`actions/runs/${runId}`), tree, directory, request);
    assert(result, 'Selected run has no successful validation and candidate for this Git tree');
    return result;
  }
  // Bound automatic discovery cost. Older evidence can be selected explicitly.
  const runs = request('actions/workflows/beacon-ci.yml/runs?status=success&per_page=30').workflow_runs;
  for (const run of runs) {
    const result = resolveValidation(run, tree, directory, request);
    if (result) return result;
  }
  return null;
}

function output(name, value) {
  if (process.env.GITHUB_OUTPUT) appendFileSync(process.env.GITHUB_OUTPUT, `${name}=${value}\n`);
}

function main([command, directory = 'release-candidate']) {
  if (command === 'stage') {
    stage(directory, JSON.parse(process.env.CI_PLAN));
    return;
  }
  if (command === 'verify-payload') {
    const evidence = JSON.parse(readFileSync(join(directory, 'ci-evidence.json'), 'utf8'));
    assert.equal(evidence.source_tree, git('rev-parse', 'HEAD^{tree}'));
    verifyPayload(directory, evidence, productVersion());
    return;
  }
  assert(['find', 'download'].includes(command), 'Expected stage, find, download or verify-payload');
  const temporary = mkdtempSync(join(tmpdir(), 'beacon-ci-evidence-'));
  try {
    const result = findValidation(git('rev-parse', 'HEAD^{tree}'), temporary, process.env.VALIDATION_RUN_ID);
    if (!result) {
      assert.equal(command, 'find', 'No reusable validation found; run Beacon CI once on this source first');
      console.log('No reusable validation; the normal build will run.');
      return;
    }
    output('reuse_run_id', result.run.id);
    const validationUrl = `https://github.com/${repository}/actions/runs/${result.run.id}`;
    console.log(`Reusing successful ${result.evidence.plan.profile} validation: ${validationUrl}`);
    if (process.env.GITHUB_STEP_SUMMARY) appendFileSync(process.env.GITHUB_STEP_SUMMARY,
      `Reused [${result.evidence.plan.profile} CI validation](${validationUrl}) for identical Git tree `
        + `\`${result.evidence.source_tree}\`.\n`);
    if (command === 'download') {
      const archive = join(temporary, 'candidate.zip');
      writeFileSync(archive, api(`actions/artifacts/${result.artifact_id}/zip`, true));
      mkdirSync(directory, { recursive: true });
      // Extract only known payload paths, never arbitrary archive entries.
      for (const file of payloads(result.evidence.version)) {
        mkdirSync(resolve(directory, file, '..'), { recursive: true });
        writeFileSync(join(directory, file), execFileSync('unzip', ['-p', archive, file], { maxBuffer: 128 * 1024 * 1024 }));
      }
      writeFileSync(join(directory, 'ci-evidence.json'), JSON.stringify(result.evidence, null, 2) + '\n');
      verifyPayload(directory, result.evidence, productVersion());
      output('build_commit', result.evidence.source_commit);
      output('digest', result.evidence.sha256[`beacon-javaagent-${result.evidence.version}.jar`]);
    }
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
}

if (require.main === module) {
  try { main(process.argv.slice(2)); } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}

module.exports = { findValidation, pages, payloads, resolveValidation, stage, verifyPayload, verifyValidation };

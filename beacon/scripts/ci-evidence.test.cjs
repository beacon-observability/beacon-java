// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const { createHash } = require('node:crypto');
const { mkdtempSync, mkdirSync, readFileSync, writeFileSync, rmSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');
const { test } = require('node:test');
const { plan } = require('./ci-plan.cjs');
const { findValidation, pages, payloads, resolveValidation, verifyPayload, verifyValidation } = require('./ci-evidence.cjs');

const repository = 'beacon-observability/beacon-java';
const tree = 'a'.repeat(40);
function fixture(profile = 'pr', event = 'pull_request') {
  const selected = plan([], profile === 'full', profile === 'upgrade');
  const run = { id: 42, run_attempt: 2, path: '.github/workflows/beacon-ci.yml', event,
    head_sha: 'b'.repeat(40), status: 'completed', conclusion: 'success',
    repository: { full_name: repository }, head_repository: { full_name: repository } };
  const evidence = { schema_version: 1, repository, run_id: 42, run_attempt: 1,
    source_commit: event === 'pull_request' ? 'c'.repeat(40) : run.head_sha,
    source_tree: tree, version: '1.3.4', plan: selected, candidate_artifact: 'beacon-javaagent-1',
    sha256: Object.fromEntries(payloads('1.3.4').map((file) => [file, 'd'.repeat(64)])) };
  const commit = { sha: evidence.source_commit, tree: { sha: tree },
    parents: [{ sha: 'e'.repeat(40) }, { sha: run.head_sha }] };
  const names = ['Beacon required', 'build', 'quality', ...selected.matrix.include.map(({ java, indy, partition }) =>
    `tests (JDK ${java}, indy ${indy}, part ${partition})`)];
  if (selected.muzzle) for (let part = 1; part <= 4; part += 1) names.push(`muzzle / muzzle (:instrumentation:muzzle${part})`);
  if (selected.partition_check) names.push('Verify test partition coverage');
  if (selected.full) names.push('upstream-smoke', ...[0, 1, 2, 3].map((part) => `latest-deps / testLatestDeps${part}`));
  return { run, evidence, commit, jobs: names.map((name) => ({ name, conclusion: 'success', run_attempt: 1 })) };
}
function verify(value, expectedTree = tree) {
  return verifyValidation(value.run, value.jobs, value.evidence, expectedTree, value.commit);
}

test('regular, upgrade and full PR/manual validation can release an identical Git tree', () => {
  for (const profile of ['pr', 'upgrade', 'full']) {
    for (const event of ['pull_request', 'workflow_dispatch']) assert.doesNotThrow(() => verify(fixture(profile, event)));
  }
});

test('tree equivalence survives merge and squash commit identity changes but not content changes', () => {
  const value = fixture();
  assert.notEqual(value.evidence.source_commit, value.run.head_sha);
  verify(value);
  assert.throws(() => verify(value, 'f'.repeat(40)), /differs/);
  value.commit.tree.sha = 'f'.repeat(40);
  assert.throws(() => verify(value), /different content/);
});

test('foreign repositories, forks, wrong workflows, pushes and unsuccessful runs cannot supply releases', () => {
  const changes = [
    (v) => { v.run.repository.full_name = 'other/repo'; },
    (v) => { v.run.head_repository.full_name = 'fork/beacon-java'; },
    (v) => { v.run.path = '.github/workflows/other.yml'; },
    (v) => { v.run.event = 'push'; },
    (v) => { v.run.status = 'in_progress'; },
    (v) => { v.run.conclusion = 'failure'; },
    (v) => { v.evidence.run_id = 43; },
    (v) => { v.evidence.run_attempt = 3; },
    (v) => { v.evidence.run_attempt = 2; },
    (v) => { v.commit.sha = 'f'.repeat(40); },
    (v) => { v.commit.parents[1].sha = 'f'.repeat(40); },
    (v) => { v.evidence.sha256.LICENSE = 'invalid'; },
    (v) => { v.evidence.version = '../../evil'; },
    (v) => { delete v.evidence.sha256.LICENSE; },
  ];
  for (const change of changes) {
    const value = fixture();
    change(value);
    assert.throws(() => verify(value), change.toString());
  }
});

test('each selected job is required, including full-profile optional suites', () => {
  const reference = fixture('full');
  for (const job of reference.jobs) {
    for (const state of ['failure', 'cancelled', 'skipped']) {
      const value = structuredClone(reference);
      value.jobs.find((entry) => entry.name === job.name).conclusion = state;
      assert.throws(() => verify(value), undefined, `${job.name}: ${state}`);
    }
    const missing = structuredClone(reference);
    missing.jobs = missing.jobs.filter((entry) => entry.name !== job.name);
    assert.throws(() => verify(missing), undefined, job.name);
  }
});

test('matrix duplicates, substitutions and reduced profiles fail closed', () => {
  for (const mutate of [
    (v) => { v.jobs.push(v.jobs.find((job) => job.name.startsWith('tests ('))); },
    (v) => { v.jobs.find((job) => job.name.startsWith('tests (')).name = 'tests (JDK 99, indy false, part 0)'; },
    (v) => { v.evidence.plan.matrix.include.pop(); },
    (v) => { v.evidence.plan.muzzle = false; },
    (v) => { v.evidence.plan.partition_check = false; },
  ]) {
    const value = fixture('full');
    mutate(value);
    assert.throws(() => verify(value));
  }
});

test('small job pages preserve all jobs and retry attempts preserve the original successful build', () => {
  const value = fixture('full');
  let calls = 0;
  const jobs = pages('actions/runs/42/jobs?filter=latest', 'jobs', (path) => {
    assert.match(path, /per_page=30&page=[123]$/);
    const page = Number(path.match(/page=(\d+)$/)[1]);
    calls += 1;
    return { jobs: value.jobs.slice((page - 1) * 30, page * 30) };
  });
  assert.equal(calls, 3);
  assert.deepEqual(jobs, value.jobs);
  verifyValidation(value.run, jobs, value.evidence, tree, value.commit);
});

function withApiFixture(callback) {
  const dir = mkdtempSync(join(tmpdir(), 'beacon-evidence-api-'));
  const value = fixture();
  const artifacts = [
    { id: 100, name: 'beacon-ci-evidence-1', expired: false },
    { id: 101, name: 'beacon-javaagent-1', expired: false },
  ];
  writeFileSync(join(dir, 'ci-evidence.json'), JSON.stringify(value.evidence));
  execFileSync('zip', ['-q', join(dir, 'manifest.zip'), 'ci-evidence.json'], { cwd: dir });
  const request = (path, binary) => {
    if (path === 'actions/workflows/beacon-ci.yml/runs?status=success&per_page=30') return { workflow_runs: [value.run] };
    if (path === 'actions/runs/42') return value.run;
    if (path === 'actions/runs/42/artifacts?per_page=30&page=1') return { artifacts };
    if (path === 'actions/artifacts/100/zip') {
      assert.equal(binary, true);
      return readFileSync(join(dir, 'manifest.zip'));
    }
    if (path === `git/commits/${value.evidence.source_commit}`) return value.commit;
    if (path === 'actions/runs/42/jobs?filter=latest&per_page=30&page=1') return { jobs: value.jobs };
    throw new Error(`Unexpected API request: ${path}`);
  };
  try { callback({ dir, value, artifacts, request }); } finally { rmSync(dir, { recursive: true, force: true }); }
}

test('automatic and explicit discovery select the verified build artifact, never the newest artifact blindly', () => {
  withApiFixture(({ dir, request }) => {
    const result = findValidation(tree, dir, undefined, request);
    assert.equal(result.artifact_id, 101);
    assert.equal(findValidation(tree, dir, '42', request).evidence.run_id, 42);
    assert.equal(findValidation('f'.repeat(40), dir, undefined, request), null);
    assert.throws(() => findValidation('f'.repeat(40), dir, '42', request), /no successful validation/);
    assert.throws(() => findValidation(tree, dir, '../42', request), /Invalid validation run/);
  });
});

test('missing and expired candidates fall back to a build, API failures remain visible', () => {
  withApiFixture(({ dir, value, artifacts, request }) => {
    artifacts[1].expired = true;
    assert.equal(resolveValidation(value.run, tree, dir, request), null);
    artifacts.pop();
    assert.equal(resolveValidation(value.run, tree, dir, request), null);
    assert.throws(() => findValidation(tree, dir, undefined, () => { throw new Error('HTTP 502'); }), /HTTP 502/);
  });
});

test('every payload, including SBOM and smoke fixture, is digest-bound before execution', () => {
  const dir = mkdtempSync(join(tmpdir(), 'beacon-evidence-payload-'));
  const evidence = fixture().evidence;
  mkdirSync(join(dir, 'verification'));
  try {
    for (const file of payloads('1.3.4')) {
      writeFileSync(join(dir, file), file);
      evidence.sha256[file] = createHash('sha256').update(file).digest('hex');
    }
    assert.throws(() => verifyPayload(dir, evidence, '1.3.5'), /version differs/);
    for (const file of payloads('1.3.4')) {
      writeFileSync(join(dir, file), 'changed');
      assert.throws(() => verifyPayload(dir, evidence, '1.3.4'), /digest changed/);
      writeFileSync(join(dir, file), file);
    }
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('a staged, verified candidate is promoted unchanged across a merge and transient API failure', () => {
  const { stage } = require('./ci-evidence.cjs');
  const { productVersion } = require('./release-metadata.cjs');
  const dir = mkdtempSync(join(tmpdir(), 'beacon-ci-promotion-'));
  const previous = process.cwd();
  const script = join(__dirname, 'ci-evidence.cjs');
  const version = productVersion();
  const put = (name, contents) => {
    const path = join(dir, name);
    mkdirSync(join(path, '..'), { recursive: true });
    writeFileSync(path, contents);
  };
  const git = (...args) => execFileSync('git', args, { cwd: dir, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
  try {
    put('jar/META-INF/MANIFEST.MF', 'Manifest-Version: 1.0\nImplementation-Title: Beacon Java\n'
      + `Implementation-Version: ${version}\nImplementation-Vendor: Beacon Observability\nBeacon-Version: ${version}\n`
      + 'Premain-Class: io.opentelemetry.javaagent.OpenTelemetryAgent\n');
    put('jar/META-INF/beacon/version.properties', `version=${version}\n`);
    put('jar/META-INF/beacon/upstream.lock.json', '{}');
    put('jar/META-INF/beacon/security-spec.properties', 'version=2');
    put('jar/extensions/beacon-security-extension.jar', 'security extension fixture');
    put('LICENSE', 'license');
    put('licenses/licenses.md', 'third-party licenses');
    put('beacon/testing/security-smoke-fixture/build/libs/beacon-security-smoke-fixture.jar', 'smoke fixture');
    mkdirSync(join(dir, 'javaagent/build/libs'), { recursive: true });
    execFileSync('zip', ['-qr', join(dir, `javaagent/build/libs/beacon-javaagent-${version}.jar`), '.'], { cwd: join(dir, 'jar') });
    git('init', '-q');
    git('config', 'user.email', 'test@example.invalid');
    git('config', 'user.name', 'CI Test');
    git('add', '.');
    git('commit', '-qm', 'Validated source');
    const sourceCommit = git('rev-parse', 'HEAD');
    const sourceTree = git('rev-parse', 'HEAD^{tree}');
    put('javaagent/build/spdx/beacon-javaagent.spdx.json', JSON.stringify({
      name: 'beacon-javaagent',
      documentNamespace: `https://beacon-observability.github.io/spdx/beacon-javaagent/${version}/${sourceCommit}`,
      packages: [{ name: 'beacon-javaagent', versionInfo: version, supplier: 'Organization: Beacon Observability' },
        { name: 'security', versionInfo: version }, { name: 'com.fasterxml.jackson.core:jackson-databind' }],
    }));
    process.chdir(dir);
    const evidence = stage(join(dir, 'candidate'), plan([]), {
      GITHUB_SHA: sourceCommit, GITHUB_RUN_ID: '42', GITHUB_RUN_ATTEMPT: '1',
    });
    assert.equal(evidence.source_tree, sourceTree);
    verifyPayload(join(dir, 'candidate'), evidence, version);
    execFileSync('zip', ['-qr', join(dir, 'candidate.zip'), '.'], { cwd: join(dir, 'candidate') });
    execFileSync('zip', ['-q', join(dir, 'evidence.zip'), 'ci-evidence.json'], { cwd: join(dir, 'candidate') });
    git('commit', '--allow-empty', '-qm', 'Merge with identical tree');
    assert.notEqual(git('rev-parse', 'HEAD'), sourceCommit);
    const value = fixture('pr', 'workflow_dispatch');
    value.run.head_sha = sourceCommit;
    value.run.run_attempt = 1;
    const commit = { sha: sourceCommit, tree: { sha: sourceTree }, parents: [] };
    const artifacts = [{ id: 100, name: 'beacon-ci-evidence-1', expired: false },
      { id: 101, name: 'beacon-javaagent-1', expired: false }];
    const responses = {
      [`repos/${repository}/actions/runs/42`]: value.run,
      [`repos/${repository}/actions/runs/42/artifacts?per_page=30&page=1`]: { artifacts },
      [`repos/${repository}/actions/runs/42/jobs?filter=latest&per_page=30&page=1`]: { jobs: value.jobs },
      [`repos/${repository}/git/commits/${sourceCommit}`]: commit,
    };
    put('responses.json', JSON.stringify(responses));
    put('bin/gh', `#!${process.execPath}\nconst fs = require('node:fs');
const path = process.argv[3];
const root = process.env.FIXTURE_ROOT;
if (path.includes('/jobs?') && !fs.existsSync(root + '/retried')) {
  fs.writeFileSync(root + '/retried', 'yes');
  process.stderr.write('HTTP 502: Server Error'); process.exit(1);
}
if (path.endsWith('/100/zip') || path.endsWith('/101/zip')) {
  process.stdout.write(fs.readFileSync(root + (path.endsWith('/100/zip') ? '/evidence.zip' : '/candidate.zip')));
} else {
  const result = JSON.parse(fs.readFileSync(root + '/responses.json'))[path];
  if (!result) throw new Error('Unexpected API call: ' + path);
  process.stdout.write(JSON.stringify(result));
}
`);
    require('node:fs').chmodSync(join(dir, 'bin/gh'), 0o755);
    const environment = { ...process.env, PATH: join(dir, 'bin') + ':' + process.env.PATH,
      FIXTURE_ROOT: dir, VALIDATION_RUN_ID: '42', GITHUB_OUTPUT: join(dir, 'outputs') };
    const result = execFileSync(process.execPath, [script, 'download', join(dir, 'promoted')], {
      cwd: dir, env: environment, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'],
    });
    assert.match(result, /Reusing successful pr validation/);
    assert.equal(readFileSync(join(dir, 'retried'), 'utf8'), 'yes');
    for (const file of payloads(version)) {
      assert.deepEqual(readFileSync(join(dir, 'promoted', file)), readFileSync(join(dir, 'candidate', file)));
    }
    assert.match(readFileSync(join(dir, 'outputs'), 'utf8'), new RegExp(`build_commit=${sourceCommit}`));
    execFileSync(process.execPath, [script, 'verify-payload', join(dir, 'promoted')], { cwd: dir, env: environment });
    put('changed-source', 'different content');
    git('add', 'changed-source');
    git('commit', '-qm', 'Changed source');
    assert.throws(() => execFileSync(process.execPath, [script, 'download', join(dir, 'rejected')], {
      cwd: dir, env: environment, stdio: ['ignore', 'pipe', 'pipe'],
    }), /Command failed/);
  } finally {
    process.chdir(previous);
    rmSync(dir, { recursive: true, force: true });
  }
});


test('compatibility evidence uses the actual reusable workflow partition names', () => {
  const workflow = readFileSync(join(__dirname, '../../.github/workflows/reusable-muzzle.yml'), 'utf8');
  const tasks = [...workflow.matchAll(/- "(:instrumentation:muzzle[0-9]+)"/g)].map((match) => match[1]);
  const value = fixture('upgrade');
  const jobs = value.jobs.filter((job) => !job.name.startsWith('muzzle /'));
  tasks.forEach((task) => jobs.push({ name: `muzzle / muzzle (${task})`, conclusion: 'success' }));
  assert.equal(tasks.length, 4);
  verifyValidation(value.run, jobs, value.evidence, tree, value.commit);
});

test('an expired newer build cannot silently fall back to evidence for an older build attempt', () => {
  withApiFixture(({ dir, value, request }) => {
    value.jobs.find((job) => job.name === 'build').run_attempt = 2;
    assert.equal(findValidation(tree, dir, undefined, request), null);
  });
});

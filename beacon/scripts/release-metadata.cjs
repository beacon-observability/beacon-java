// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const { execFileSync } = require('node:child_process');
const {
  readFileSync, writeFileSync,
} = require('node:fs');
const { basename, resolve } = require('node:path');

const root = resolve(__dirname, '../..');
const versionFile = resolve(root, 'beacon/version.properties');
const changelogFile = resolve(root, 'beacon/CHANGELOG.md');
const releaseVersionPattern = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-rc\.(0|[1-9]\d*))?$/;

function productVersion() {
  const match = readFileSync(versionFile, 'utf8').match(/^version=(.+)$/m);
  assert(match, 'beacon/version.properties does not contain version');
  return match[1];
}

function assertReleaseVersion(version) {
  assert(releaseVersionPattern.test(version),
    `Invalid release version ${version}; expected X.Y.Z or X.Y.Z-rc.N`);
}

function changelogSection(version) {
  const changelog = readFileSync(changelogFile, 'utf8');
  const escaped = version.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const match = changelog.match(new RegExp(
    `^## Version ${escaped} \\([0-9]{4}-[0-9]{2}-[0-9]{2}\\)\\n([\\s\\S]*?)(?=^## Version |(?![\\s\\S]))`,
    'm',
  ));
  assert(match, `Missing changelog section for ${version}`);
  const section = match[1].trim();
  assert(section, `Changelog section for ${version} is empty`);
  return section;
}

function validateSource(expected) {
  const version = productVersion();
  assertReleaseVersion(version);
  if (expected) assert.equal(version, expected, 'Requested version differs from source version');
  changelogSection(version);
  return version;
}

function versionParts(version) {
  const match = version.match(releaseVersionPattern);
  assert(match, `Invalid release version ${version}`);
  return match.slice(1).map((value) => value === undefined ? Number.MAX_SAFE_INTEGER : Number(value));
}

function compareVersions(left, right) {
  const leftParts = versionParts(left);
  const rightParts = versionParts(right);
  for (let index = 0; index < leftParts.length; index += 1) {
    if (leftParts[index] !== rightParts[index]) return leftParts[index] - rightParts[index];
  }
  return 0;
}

function prepare(version, date) {
  assertReleaseVersion(version);
  assert.match(date, /^\d{4}-\d{2}-\d{2}$/, 'Release date must use YYYY-MM-DD');
  const current = productVersion();
  assertReleaseVersion(current);
  assert(compareVersions(version, current) > 0,
    `Release version ${version} must be newer than ${current}`);

  const changelog = readFileSync(changelogFile, 'utf8');
  assert(!changelog.includes(`## Version ${version} (`), `Changelog already contains ${version}`);
  const match = changelog.match(/^## Unreleased\n([\s\S]*?)(?=^## Version )/m);
  assert(match, 'Missing Unreleased changelog section');
  const pending = match[1].trim();
  assert(pending, 'Unreleased changelog section is empty');
  const replacement = `## Unreleased\n\n## Version ${version} (${date})\n\n${pending}\n\n`;
  writeFileSync(changelogFile, changelog.replace(match[0], replacement));
  writeFileSync(versionFile,
    readFileSync(versionFile, 'utf8').replace(/^version=.*$/m, `version=${version}`));
  validateSource(version);
}

function parseManifest(contents) {
  const attributes = new Map();
  let key;
  for (const line of contents.replace(/\r/g, '').split('\n')) {
    if (line.startsWith(' ') && key) {
      attributes.set(key, attributes.get(key) + line.slice(1));
      continue;
    }
    const separator = line.indexOf(': ');
    if (separator > 0) {
      key = line.slice(0, separator);
      attributes.set(key, line.slice(separator + 2));
    }
  }
  return attributes;
}

function zipEntry(file, entry) {
  return execFileSync('unzip', ['-p', file, entry], { encoding: 'utf8', maxBuffer: 1024 * 1024 });
}

function hasZipEntry(file, entry) {
  return execFileSync('unzip', ['-Z1', file, entry], {
    encoding: 'utf8', maxBuffer: 1024 * 1024,
  }).trim() === entry;
}

function verifyArtifact(file, version, expectedDigest) {
  assertReleaseVersion(version);
  const resolved = resolve(file);
  assert.equal(basename(resolved), `beacon-javaagent-${version}.jar`, 'Unexpected artifact file name');
  const manifest = parseManifest(zipEntry(resolved, 'META-INF/MANIFEST.MF'));
  const expected = {
    'Implementation-Title': 'Beacon Java',
    'Implementation-Version': version,
    'Implementation-Vendor': 'Beacon Observability',
    'Beacon-Version': version,
    'Premain-Class': 'io.opentelemetry.javaagent.OpenTelemetryAgent',
  };
  for (const [key, value] of Object.entries(expected)) {
    assert.equal(manifest.get(key), value, `Incorrect Manifest attribute ${key}`);
  }
  assert.equal(zipEntry(resolved, 'META-INF/beacon/version.properties').trim().split('\n')
    .find((line) => line.startsWith('version=')), `version=${version}`);
  assert(hasZipEntry(resolved, 'extensions/beacon-security-extension.jar'),
    'Missing embedded Beacon Security extension');
  assert(hasZipEntry(resolved, 'META-INF/beacon/upstream.lock.json'),
    'Missing embedded upstream provenance');
  assert(hasZipEntry(resolved, 'META-INF/beacon/security-spec.properties'),
    'Missing embedded Security specification provenance');
  const digest = createHash('sha256').update(readFileSync(resolved)).digest('hex');
  if (expectedDigest) assert.equal(digest, expectedDigest, 'Artifact digest changed');
  return digest;
}

function verifySbom(file, version, sourceCommit) {
  assertReleaseVersion(version);
  assert.match(sourceCommit, /^[0-9a-f]{40}$/);
  const sbom = JSON.parse(readFileSync(resolve(file), 'utf8'));
  assert.equal(sbom.name, 'beacon-javaagent', 'Incorrect SPDX document name');
  assert.equal(sbom.documentNamespace,
    `https://beacon-observability.github.io/spdx/beacon-javaagent/${version}/${sourceCommit}`,
    'SPDX document does not identify the release source');
  assert(Array.isArray(sbom.packages), 'SPDX document does not contain packages');

  const findPackage = (name) => sbom.packages.find((candidate) => candidate.name === name);
  const agent = findPackage('beacon-javaagent');
  assert(agent, 'SPDX document is missing Beacon Java');
  assert.equal(agent.versionInfo, version, 'SPDX Beacon Java version differs from the release');
  assert.equal(agent.supplier, 'Organization: Beacon Observability',
    'SPDX Beacon Java supplier is incorrect');

  const security = findPackage('security');
  assert(security, 'SPDX document is missing Beacon Security');
  assert.equal(security.versionInfo, version,
    'SPDX Beacon Security version differs from the release');
  assert(findPackage('com.fasterxml.jackson.core:jackson-databind'),
    'SPDX document is missing a Beacon Security runtime dependency');
}

function jobsFrom(value) {
  if (Array.isArray(value)) return value.flatMap(jobsFrom);
  if (value && Array.isArray(value.jobs)) return value.jobs;
  return [];
}

function verifyCi(runFile, jobsFile, sourceCommit) {
  assert.match(sourceCommit, /^[0-9a-f]{40}$/);
  const run = JSON.parse(readFileSync(runFile, 'utf8'));
  assert.equal(run.path, '.github/workflows/beacon-ci.yml', 'Validation used the wrong workflow');
  assert.equal(run.event, 'workflow_dispatch', 'Validation must be a manual full run');
  assert.equal(run.head_sha, sourceCommit, 'Validation commit differs from release source');
  assert.equal(run.status, 'completed', 'Validation is not complete');
  assert.equal(run.conclusion, 'success', 'Validation did not succeed');
  assert.equal(run.repository.full_name, 'beacon-observability/beacon-java',
    'Validation came from the wrong repository');

  const jobs = jobsFrom(JSON.parse(readFileSync(jobsFile, 'utf8')));
  const requireSuccess = (name) => {
    const job = jobs.find((candidate) => candidate.name === name);
    assert(job, `Validation is missing ${name}`);
    assert.equal(job.conclusion, 'success', `${name} did not succeed`);
  };
  requireSuccess('Beacon required');
  requireSuccess('upstream-smoke');
  const matrix = jobs.filter((job) => job.name.startsWith('tests (JDK '));
  assert.equal(matrix.length, 48, 'Validation did not run the 48-job full JDK matrix');
  for (const job of matrix) assert.equal(job.conclusion, 'success', `${job.name} did not succeed`);
}

function writeNotes(version, output, sourceCommit, digest, validationUrl) {
  assert.match(sourceCommit, /^[0-9a-f]{40}$/);
  assert.match(digest, /^[0-9a-f]{64}$/);
  assert.match(validationUrl, /^https:\/\/github\.com\/beacon-observability\/beacon-java\/actions\/runs\/\d+$/);
  const section = changelogSection(version);
  writeFileSync(output, `${section}\n\n### Release evidence\n\n`
    + `- Source commit: \`${sourceCommit}\`\n`
    + `- Full validation: ${validationUrl}\n`
    + `- Agent SHA-256: \`${digest}\`\n`
    + '- The attached JAR is the exact candidate tested by this release workflow; the publish job does not rebuild it.\n');
}

function main(args) {
  const [command, ...rest] = args;
  if (command === 'version') {
    process.stdout.write(`${productVersion()}\n`);
  } else if (command === 'validate-source') {
    process.stdout.write(`${validateSource(rest[0])}\n`);
  } else if (command === 'prepare') {
    assert(rest[0], 'Usage: prepare <version> [YYYY-MM-DD]');
    prepare(rest[0], rest[1] || new Date().toISOString().slice(0, 10));
  } else if (command === 'verify-artifact') {
    assert(rest[0] && rest[1], 'Usage: verify-artifact <jar> <version> [sha256]');
    process.stdout.write(`${verifyArtifact(rest[0], rest[1], rest[2])}\n`);
  } else if (command === 'verify-sbom') {
    assert(rest[0] && rest[1] && rest[2], 'Usage: verify-sbom <spdx.json> <version> <commit>');
    verifySbom(rest[0], rest[1], rest[2]);
  } else if (command === 'verify-ci') {
    assert(rest[0] && rest[1] && rest[2], 'Usage: verify-ci <run.json> <jobs.json> <commit>');
    verifyCi(rest[0], rest[1], rest[2]);
  } else if (command === 'write-notes') {
    assert(rest.length === 5,
      'Usage: write-notes <version> <output> <commit> <sha256> <validation-url>');
    writeNotes(...rest);
  } else {
    throw new Error('Usage: release-metadata.cjs <version|validate-source|prepare|verify-artifact|verify-sbom|verify-ci|write-notes> ...');
  }
}

if (require.main === module) {
  try {
    main(process.argv.slice(2));
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}

module.exports = {
  assertReleaseVersion, changelogSection, compareVersions, jobsFrom, parseManifest, verifyCi,
  verifySbom,
};

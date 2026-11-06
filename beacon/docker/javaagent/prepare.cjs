// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const { mkdirSync, readFileSync, readdirSync } = require('node:fs');
const { resolve } = require('node:path');
const { verifyProvenance } = require('./release-provenance.cjs');

const repository = 'beacon-observability/beacon-java';
const [version, destination] = process.argv.slice(2);
assert(version && destination, 'Usage: node prepare.cjs <X.Y.Z> <empty-directory>');
assert.match(version, /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/);
const stage = resolve(destination);
mkdirSync(stage, { recursive: true });
assert.equal(readdirSync(stage).length, 0, 'The staging directory must be empty');

function gh(args) {
  return execFileSync('gh', args, { encoding: 'utf8', maxBuffer: 1024 * 1024 });
}

const tag = `v${version}`;
const release = JSON.parse(gh(['release', 'view', tag, '--repo', repository,
  '--json', 'tagName,isDraft,isPrerelease']));
assert.equal(release.tagName, tag);
assert.equal(release.isDraft, false, 'Cannot package a draft release');
assert.equal(release.isPrerelease, false, 'This image channel accepts stable releases only');
const releaseCommit = JSON.parse(gh(['api', `repos/${repository}/commits/${tag}`]));
const source = releaseCommit.sha;
assert.match(source, /^[0-9a-f]{40}$/);

const agent = `beacon-javaagent-${version}.jar`;
const sbom = `beacon-javaagent-${version}.spdx.json`;
const assets = [agent, `${agent}.sha256`, sbom, 'LICENSE', 'THIRD_PARTY_LICENSES.md', 'provenance.json'];
gh(['release', 'download', tag, '--repo', repository, '--dir', stage,
  ...assets.flatMap((name) => ['--pattern', name])]);
const checksum = readFileSync(resolve(stage, `${agent}.sha256`), 'utf8').trim();
const match = checksum.match(/^([0-9a-f]{64}) {2}(.+)$/);
assert(match, 'Invalid release checksum');
assert.equal(match[2], agent, 'Checksum names a different artifact');
const verifier = resolve(__dirname, '../../scripts/release-metadata.cjs');
execFileSync(process.execPath, [verifier, 'verify-artifact', resolve(stage, agent), version, match[1]],
  { stdio: 'inherit' });
const provenance = JSON.parse(readFileSync(resolve(stage, 'provenance.json'), 'utf8'));
const buildSource = verifyProvenance(provenance,
  { version, source, sourceTree: releaseCommit.commit.tree.sha, digest: match[1] },
  (commit) => gh(['api', `repos/${repository}/commits/${commit}`, '--jq', '.commit.tree.sha']).trim());
execFileSync(process.execPath, [verifier, 'verify-sbom', resolve(stage, sbom), version, buildSource],
  { stdio: 'inherit' });
console.log(JSON.stringify({ version, source, agent_sha256: match[1], stage }, null, 2));

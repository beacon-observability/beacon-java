// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

const assert = require('node:assert/strict');
const test = require('node:test');
const { verifyProvenance } = require('../docker/javaagent/release-provenance.cjs');

const source = 'a'.repeat(40);
const buildSource = 'b'.repeat(40);
const sourceTree = 'c'.repeat(40);
const digest = 'd'.repeat(64);
const expected = { version: '1.3.5', source, sourceTree, digest };
const legacy = {
  product: 'Beacon Java', version: '1.3.5',
  source_repository: 'https://github.com/beacon-observability/beacon-java',
  source_commit: source, agent_sha256: digest,
};
const promoted = { ...legacy, build_source_commit: buildSource, source_tree: sourceTree };

function unexpectedLookup() {
  assert.fail('A legacy or same-commit release must not look up another commit');
}

test('legacy releases verify the SBOM against the release commit', () => {
  assert.equal(verifyProvenance(legacy, expected, unexpectedLookup), source);
});

test('promoted releases retain the build commit for SBOM verification', () => {
  const requested = [];
  assert.equal(verifyProvenance(promoted, expected, (commit) => {
    requested.push(commit);
    return sourceTree;
  }), buildSource);
  assert.deepEqual(requested, [buildSource]);
});

test('same-commit provenance does not require another commit lookup', () => {
  assert.equal(verifyProvenance({ ...promoted, build_source_commit: source }, expected,
    unexpectedLookup), source);
});

for (const [name, change] of [
  ['a different product', { product: 'Other' }],
  ['a different version', { version: '1.3.4' }],
  ['a different repository', { source_repository: 'https://example.com/other' }],
  ['a different release commit', { source_commit: 'e'.repeat(40) }],
  ['a different Agent digest', { agent_sha256: 'e'.repeat(64) }],
  ['an invalid build commit', { build_source_commit: 'not-a-commit' }],
  ['a null build commit', { build_source_commit: null }],
  ['a missing source tree', { source_tree: undefined }],
  ['a different release tree', { source_tree: 'e'.repeat(40) }],
]) {
  test(`rejects ${name}`, () => {
    assert.throws(() => verifyProvenance({ ...promoted, ...change }, expected, () => sourceTree));
  });
}

test('rejects a build commit with different content', () => {
  assert.throws(() => verifyProvenance(promoted, expected, () => 'e'.repeat(40)),
    /Build and release source trees differ/);
});

test('fails visibly when build commit lookup fails', () => {
  assert.throws(() => verifyProvenance(promoted, expected, () => {
    throw new Error('GitHub unavailable');
  }), /GitHub unavailable/);
});

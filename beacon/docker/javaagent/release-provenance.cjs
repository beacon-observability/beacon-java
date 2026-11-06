// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

const assert = require('node:assert/strict');

function verifyProvenance(provenance, { version, source, sourceTree, digest }, getTree) {
  assert.equal(provenance.product, 'Beacon Java');
  assert.equal(provenance.version, version);
  assert.equal(provenance.source_repository, 'https://github.com/beacon-observability/beacon-java');
  assert.equal(provenance.source_commit, source, 'Release provenance differs from the tag');
  assert.equal(provenance.agent_sha256, digest);

  if (provenance.build_source_commit === undefined) {
    return source;
  }
  const buildSource = provenance.build_source_commit;
  assert.match(buildSource, /^[0-9a-f]{40}$/, 'Invalid build source commit');
  assert.match(provenance.source_tree, /^[0-9a-f]{40}$/, 'Invalid source tree');
  assert.equal(provenance.source_tree, sourceTree, 'Release source tree differs from provenance');
  if (buildSource !== source) {
    assert.equal(getTree(buildSource), sourceTree, 'Build and release source trees differ');
  }
  return buildSource;
}

module.exports = { verifyProvenance };

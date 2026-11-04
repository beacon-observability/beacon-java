// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

const assert = require('node:assert/strict');
const {
  mkdtempSync, rmSync, writeFileSync,
} = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');
const { test } = require('node:test');
const {
  assertReleaseVersion, compareVersions, parseManifest, verifySbom,
} = require('./release-metadata.cjs');

test('release versions are stable versions or numbered release candidates', () => {
  for (const version of ['1.0.0', '12.34.56', '2.0.0-rc.1']) {
    assert.doesNotThrow(() => assertReleaseVersion(version));
  }
  for (const version of ['1.0', '1.0.0-SNAPSHOT', 'v1.0.0', '1.0.0-rc.one', '../1.0.0']) {
    assert.throws(() => assertReleaseVersion(version));
  }
});

test('release version comparison treats stable as newer than its release candidates', () => {
  assert(compareVersions('1.1.0', '1.0.0') > 0);
  assert(compareVersions('1.1.0-rc.2', '1.1.0-rc.1') > 0);
  assert(compareVersions('1.1.0', '1.1.0-rc.2') > 0);
  assert.equal(compareVersions('1.1.0', '1.1.0'), 0);
});

test('Manifest parser joins continuation lines', () => {
  const manifest = parseManifest('Manifest-Version: 1.0\r\nLong: first\r\n second\r\n\r\n');
  assert.equal(manifest.get('Manifest-Version'), '1.0');
  assert.equal(manifest.get('Long'), 'firstsecond');
});

test('release SBOM identifies the release source and embedded Security component', () => {
  const directory = mkdtempSync(join(tmpdir(), 'beacon-release-sbom-'));
  const file = join(directory, 'beacon-javaagent.spdx.json');
  const sourceCommit = 'a'.repeat(40);
  const sbom = {
    name: 'beacon-javaagent',
    documentNamespace: `https://beacon-observability.github.io/spdx/beacon-javaagent/1.1.0/${sourceCommit}`,
    packages: [
      {
        name: 'beacon-javaagent',
        versionInfo: '1.1.0',
        supplier: 'Organization: Beacon Observability',
      },
      { name: 'security', versionInfo: '1.1.0' },
      { name: 'com.fasterxml.jackson.core:jackson-databind', versionInfo: '2.20.1' },
    ],
  };
  try {
    writeFileSync(file, JSON.stringify(sbom));
    assert.doesNotThrow(() => verifySbom(file, '1.1.0', sourceCommit));
    sbom.packages = sbom.packages.filter((entry) => entry.name !== 'security');
    writeFileSync(file, JSON.stringify(sbom));
    assert.throws(() => verifySbom(file, '1.1.0', sourceCommit), /missing Beacon Security/);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

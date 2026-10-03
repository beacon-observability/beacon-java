// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { resolve } = require('node:path');
const { test } = require('node:test');

const root = resolve(__dirname, '../..');
const release = readFileSync(resolve(root, '.github/workflows/beacon-release.yml'), 'utf8');
const prepare = readFileSync(resolve(root, '.github/workflows/beacon-prepare-release.yml'), 'utf8');

test('Beacon release is isolated from inherited publication and uses a protected promotion job', () => {
  assert.match(release, /github\.repository == 'beacon-observability\/beacon-java'/);
  assert.match(release, /^  publish:\n[\s\S]*?    environment: beacon-release$/m);
  assert.match(release, /needs: candidate/);
  assert.doesNotMatch(release, /publishToSonatype|uploadReleaseBundle|publishPlugins/);
  assert.doesNotMatch(release, /continue-on-error:/);
});

test('candidate validation is bound to the exact full CI source commit', () => {
  assert.match(release, /validation_run_id:/);
  assert.match(release, /release-metadata\.cjs verify-ci[\s\S]*?\$GITHUB_SHA/);
  assert.match(release, /jobs\?filter=latest&per_page=100/);
  assert.doesNotMatch(release, /gh api[^\n]*--slurp/);
  assert.match(release, /:javaagent:assemble :javaagent:verifyBeaconAgent :javaagent:spdxSbom/);
  assert.match(release, /security-smoke\.cjs/);
  assert.match(release, /cache-disabled: true/);
});

test('publish promotes the uploaded candidate without rebuilding it', () => {
  const publish = release.split('\n  publish:\n')[1];
  assert.match(publish, /actions\/download-artifact@/);
  assert.match(publish, /release-metadata\.cjs verify-artifact/);
  assert.match(publish, /actions\/attest-build-provenance@/);
  assert.match(publish, /gh release create/);
  assert.match(publish, /--title "\$TAG"/);
  assert.match(publish, /gh release download/);
  assert.doesNotMatch(publish, /\.\/gradlew|assemble|spdxSbom/);
});

test('release preparation changes only release metadata and requests full CI', () => {
  assert.match(prepare, /github\.ref != 'refs\/heads\/main'/);
  assert.match(prepare, /release-metadata\.cjs prepare/);
  assert.match(prepare, /git add beacon\/version\.properties beacon\/CHANGELOG\.md/);
  assert.match(prepare, /gh workflow run beacon-ci\.yml --ref "\$branch" -f full=true/);
});

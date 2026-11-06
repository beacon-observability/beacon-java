// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

const assert = require('node:assert/strict');
const test = require('node:test');
const { expectedDistroName } = require('./agent-smoke.cjs');

for (const declarative of [false, true]) {
  test(`current source always requires Beacon identity (declarative=${declarative})`, () => {
    assert.equal(expectedDistroName(undefined, declarative), 'beacon-java-instrumentation');
  });
  for (const version of ['1.3.2', '1.3.4']) {
    test(`immutable ${version} retains its previous name (declarative=${declarative})`, () => {
      assert.equal(expectedDistroName(version, declarative),
        declarative ? 'opentelemetry-javaagent' : 'opentelemetry-java-instrumentation');
    });
  }
  for (const version of ['1.3.5', '1.3.5-rc.1', '1.3.5-SNAPSHOT', '1.3.10', '1.4.0', '2.0.0']) {
    test(`immutable ${version} requires Beacon identity (declarative=${declarative})`, () => {
      assert.equal(expectedDistroName(version, declarative), 'beacon-java-instrumentation');
    });
  }
}

test('rejects malformed release versions', () => {
  for (const version of ['', 'not-a-version']) {
    assert.throws(() => expectedDistroName(version, false), /Invalid released Agent version/);
  }
});

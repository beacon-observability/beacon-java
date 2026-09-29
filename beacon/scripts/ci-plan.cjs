// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

const { execFileSync } = require('node:child_process');
const { appendFileSync } = require('node:fs');

function plan(files, full = false, unknownBase = false) {
  // Shared build/runtime changes need cross-JDK regression, not just upstream.lock changes.
  const broad = unknownBase || files.some((file) =>
    /^(beacon\/upstream\.lock\.json|version\.gradle\.kts|settings\.gradle\.kts|build\.gradle\.kts|gradle\.properties|\.java-version)$/.test(file) ||
    /^(gradle\/|conventions\/|dependencyManagement\/|javaagent[^/]*\/|instrumentation-api[^/]*\/|testing[^/]*\/|buildscripts\/|declarative-config-bridge\/|instrumentation-annotations\/|bom[^/]*\/|custom-checks\/|\.github\/|beacon\/scripts\/)/.test(file) ||
    /^beacon\/(agent\.gradle\.kts|version\.properties)$/.test(file));
  const modes = full
    ? [8, 11, 17, 21, 25, 26].flatMap((java) => [false, true].map((indy) => ({ java, indy })))
    : broad
      ? [
        { java: 8, indy: false },
        { java: 17, indy: true },
        { java: 21, indy: false },
        { java: 21, indy: true },
      ]
      : [
        { java: 21, indy: false },
        { java: 21, indy: true },
      ];
  const matrix = {
    include: modes.flatMap(({ java, indy }) =>
      [0, 1, 2, 3].map((partition) => ({ java, indy, partition }))),
  };
  return {
    profile: full ? 'full' : broad ? 'upgrade' : 'pr',
    matrix,
    muzzle: full || broad || files.some((file) => file.startsWith('instrumentation/')),
    full,
  };
}

if (require.main === module) {
  const base = process.env.CI_BASE_SHA || '';
  const unknownBase = !/^[0-9a-f]{40}$/.test(base) || /^0+$/.test(base);
  const files = unknownBase ? [] : execFileSync('git',
    ['diff', '--name-only', '-z', base, 'HEAD'], { encoding: 'utf8', maxBuffer: 16 * 1024 * 1024 })
    .split('\0').filter(Boolean);
  const result = plan(files, process.env.CI_FULL === 'true', unknownBase);
  console.log(JSON.stringify(result, null, 2));
  if (process.env.GITHUB_OUTPUT) {
    for (const [key, value] of Object.entries(result)) {
      appendFileSync(process.env.GITHUB_OUTPUT, `${key}=${typeof value === 'object' ? JSON.stringify(value) : value}\n`);
    }
  }
}

module.exports = { plan };

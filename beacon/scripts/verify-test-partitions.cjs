// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

const assert = require('node:assert/strict');
const { readFileSync, writeFileSync } = require('node:fs');
const { resolve } = require('node:path');

function verify(baseline, legacyFirst, optimized) {
  assert.deepEqual([...legacyFirst].sort(), [...baseline['0']].sort(),
    'Recorded baseline differs from the legacy collector output');
  const seen = new Set();
  let count = 0;
  for (let partition = 0; partition < 4; partition += 1) {
    const previous = baseline[String(partition)];
    const current = optimized[partition];
    assert(previous.length > 0 && current.length > 0, `Empty partition ${partition}`);
    const names = new Set(current);
    for (const task of previous) assert(names.has(task), `Missing partition ${partition} task: ${task}`);
    for (const task of current) {
      assert.match(task, /^:[A-Za-z0-9_.:-]+$/);
      assert(!seen.has(task), `Duplicate test task: ${task}`);
      seen.add(task);
      assert(previous.includes(task), `Unexpected partition ${partition} task: ${task}`);
    }
    count += previous.length;
  }
  return { baseline_tasks: count, optimized_tasks: seen.size, added_tasks: [] };
}

if (require.main === module) {
  const directory = resolve(process.argv[2] || 'build/beacon-ci');
  const lines = (name) => readFileSync(resolve(directory, name), 'utf8').trim().split(/\r?\n/);
  const report = verify(
    JSON.parse(readFileSync(resolve(directory, 'legacy-test-partitions.json'), 'utf8')),
    lines('legacy-partition-0.txt'),
    [0, 1, 2, 3].map((index) => lines(`optimized-partition-${index}.txt`)),
  );
  writeFileSync(resolve(directory, 'partition-coverage.json'), `${JSON.stringify(report, null, 2)}\n`);
  console.log(`Verified exactly ${report.baseline_tasks} baseline test tasks across four disjoint partitions.`);
}

module.exports = { verify };

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

const { spawn, execFileSync } = require('node:child_process');
const { mkdtempSync, readFileSync, rmSync } = require('node:fs');
const { get } = require('node:http');
const { tmpdir } = require('node:os');
const { join, resolve } = require('node:path');
const assert = require('node:assert/strict');
const pause = (ms) => new Promise((done) => setTimeout(done, ms));
function median(values) { return [...values].sort((a, b) => a - b)[Math.floor(values.length / 2)]; }
async function bounded(promise, ms) {
  let timer;
  try { return await Promise.race([promise, new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error('benchmark timeout')), ms);
  })]); } finally { clearTimeout(timer); }
}
function request(port) {
  return new Promise((done, reject) => {
    const call = get(`http://127.0.0.1:${port}/bench`, (response) => {
      const chunks = [];
      response.on('data', (data) => chunks.push(data));
      response.on('end', () => {
        try { done(JSON.parse(Buffer.concat(chunks).toString('utf8'))); } catch (error) { reject(error); }
      });
    });
    call.setTimeout(10000, () => call.destroy(new Error('request timeout')));
    call.on('error', reject);
  });
}
async function run(agent, enabled, classes) {
  const directory = mkdtempSync(join(tmpdir(), 'beacon-hotpath-'));
  const java = process.env.JAVA_HOME ? join(process.env.JAVA_HOME, 'bin', 'java') : 'java';
  const child = spawn(java, [`-javaagent:${agent}`, '-Dotel.traces.exporter=none',
    '-Dotel.metrics.exporter=none', '-Dotel.logs.exporter=none',
    `-Dbeacon.security.enabled=${enabled}`, '-Dbeacon.security.sbom.enabled=false',
    '-Dbeacon.security.local-output.enabled=true', `-Dbeacon.security.output=${directory}`,
    '-cp', classes, 'beacon.benchmark.SecurityHotpath'], { stdio: ['ignore', 'pipe', 'pipe'] });
  let stdout = ''; let stderr = '';
  const exited = new Promise((done) => child.once('exit', done));
  child.stderr.on('data', (data) => { stderr += data.toString(); });
  try {
    const port = await bounded(new Promise((done, reject) => {
      child.once('error', reject);
      child.stdout.on('data', (data) => {
        stdout += data.toString();
        const match = stdout.match(/PORT (\d+)/);
        if (match) done(Number(match[1]));
      });
    }), 30000);
    const inactive = JSON.parse(stdout.match(/INACTIVE (\{[^\n]+\})/)[1]);
    for (let i = 0; i < 6; i++) await request(port);
    const active = [];
    for (let i = 0; i < 10; i++) active.push(await request(port));
    if (enabled) {
      let health;
      for (let i = 0; i < 100; i++) {
        try { health = JSON.parse(readFileSync(join(directory, 'health.json'), 'utf8')); } catch {}
        if (health?.counts?.requests_started >= 16) break;
        await pause(50);
      }
      assert(health?.counts?.requests_started >= 16, 'benchmark must execute inside tracked HTTP requests');
    }
    assert(active.every((value) => value.checksum === 500000));
    return { agent, enabled, inactive, active_samples: active,
      active_median_nanos: median(active.map((value) => value.nanos)),
      active_median_allocated_bytes: median(active.map((value) => value.allocated_bytes)) };
  } catch (error) { throw new Error(`${error.message}\n${stderr}`); }
  finally {
    child.kill('SIGTERM');
    try { await bounded(exited, 10000); } catch { child.kill('SIGKILL'); await exited; }
    rmSync(directory, { recursive: true, force: true });
  }
}
async function main() {
  assert(process.argv[2] && process.argv[3], 'Usage: node security-hotpath-benchmark.cjs <baseline.jar> <fixed.jar>');
  const directory = mkdtempSync(join(tmpdir(), 'beacon-hotpath-classes-'));
  try {
    const javac = process.env.JAVA_HOME ? join(process.env.JAVA_HOME, 'bin', 'javac') : 'javac';
    execFileSync(javac, ['--release', '11', '-d', directory, join(__dirname, 'fixtures/SecurityHotpath.java')]);
    const baseline = resolve(process.argv[2]); const fixed = resolve(process.argv[3]);
    const results = [];
    results.push(await run(fixed, false, directory));
    results.push(await run(baseline, true, directory));
    results.push(await run(fixed, true, directory));
    console.log(JSON.stringify({ java_home: process.env.JAVA_HOME, results }, null, 2));
  } finally { rmSync(directory, { recursive: true, force: true }); }
}
main().catch((error) => { console.error(error); process.exitCode = 1; });

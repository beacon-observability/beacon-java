// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

const assert = require('node:assert/strict');
const { spawn, execFileSync } = require('node:child_process');
const { mkdtempSync, readdirSync, rmSync } = require('node:fs');
const { createServer } = require('node:http');
const { tmpdir } = require('node:os');
const { join, resolve } = require('node:path');

async function run(java, args, deadline = 35000, onChild = () => {}) {
  const child = spawn(java, args, { stdio: ['ignore', 'pipe', 'pipe'] });
  onChild(child);
  let output = ''; let exiting;
  const capture = (chunk) => {
    output += chunk.toString();
    if (!exiting && output.includes('EXITING')) exiting = Date.now();
  };
  child.stdout.on('data', capture); child.stderr.on('data', capture);
  let timer;
  try {
    await new Promise((done, reject) => {
      timer = setTimeout(() => { child.kill('SIGKILL'); reject(new Error(`JVM timeout: ${output}`)); }, deadline);
      child.once('error', reject);
      child.once('exit', (code, signal) => {
        if (code === 0) done(); else reject(new Error(`JVM exited ${code}/${signal}: ${output}`));
      });
    });
    return { output, shutdown_millis: exiting ? Date.now() - exiting : null };
  } finally { clearTimeout(timer); }
}

async function main() {
  assert(process.argv[2], 'Usage: node beacon/scripts/profiling-shutdown-smoke.cjs <agent.jar>');
  const java = process.env.JAVA_HOME ? join(process.env.JAVA_HOME, 'bin/java') : 'java';
  const javac = process.env.JAVA_HOME ? join(process.env.JAVA_HOME, 'bin/javac') : 'javac';
  const directory = mkdtempSync(join(tmpdir(), 'beacon-profiling-shutdown-'));
  const agent = resolve(process.argv[2]);
  const base = [`-javaagent:${agent}`, '-Dotel.traces.exporter=none', '-Dotel.metrics.exporter=none',
    '-Dotel.logs.exporter=none', '-Dotel.profiling.enabled=true', '-Dotel.profiling.interval=500ms'];
  const results = [];
  try {
    execFileSync(javac, ['--release', '11', '-d', directory, join(__dirname, 'fixtures/ProfilingShutdownProbe.java')]);
    for (let i = 0; i < 3; i++) {
      const files = join(directory, `files-${i}`); const staging = join(directory, `staging-${i}`);
      const result = await run(java, [...base, '-Dotel.profiling.exporter=file',
        `-Dotel.profiling.temp-dir=${staging}`, `-Dotel.profiling.experimental.file-export.path=${files}`,
        '-cp', directory, 'ProfilingShutdownProbe', 'run', files]);
      const check = execFileSync(java, ['-cp', directory, 'ProfilingShutdownProbe', 'check', files], { encoding: 'utf8' });
      assert(check.includes('FINAL_MARKER_PRESENT'), result.output);
      assert(readdirSync(staging).every((file) => !file.endsWith('.jfr')), 'staging files must be deleted');
      results.push({ mode: 'file', iteration: i, final_marker: true });
    }
    let uploads = 0; let activeChild; const sockets = new Set();
    const receiver = createServer((request) => {
      uploads++; request.pause(); request.socket.pause();
      // Capture the actual blocked writer, rather than infer it from a missing response.
      setTimeout(() => { if (activeChild?.exitCode === null) activeChild.kill('SIGQUIT'); }, 500);
    });
    receiver.on('connection', (socket) => { sockets.add(socket); socket.on('close', () => sockets.delete(socket)); });
    await new Promise((done) => receiver.listen(0, '127.0.0.1', done));
    try {
      const result = await run(java, [...base, '-Dotel.profiling.exporter=datakit',
        `-Dotel.profiling.endpoint=http://127.0.0.1:${receiver.address().port}/profiling/v1/input`,
        '-Dotel.profiling.datakit.timeout=60s', '-cp', directory, 'ProfilingShutdownProbe', 'slow', directory], 35000, (child) => { activeChild = child; });
      assert(uploads > 0, 'receiver must see an in-flight upload');
      assert(result.shutdown_millis !== null && result.shutdown_millis < 13000, result.output);
      assert(result.output.includes('Profiling shutdown exceeded 10 seconds'), result.output);
      assert(/SocketOutputStream.socketWrite|NioSocketImpl.implWrite|SocketDispatcher.write0/.test(result.output), result.output);
      assert(result.output.includes('DatakitProfileExporterAdapter'), result.output);
      results.push({ mode: 'unresponsive-receiver', uploads, blocked_socket_writer: true, shutdown_millis: result.shutdown_millis });
    } finally {
      for (const socket of sockets) socket.destroy();
      await new Promise((done) => receiver.close(done));
    }
    console.log(JSON.stringify({ java_home: process.env.JAVA_HOME, results }, null, 2));
  } finally { rmSync(directory, { recursive: true, force: true }); }
}
main().catch((error) => { console.error(error); process.exitCode = 1; });

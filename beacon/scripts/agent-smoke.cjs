// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const { mkdtempSync, rmSync, existsSync, readFileSync, writeFileSync } = require('node:fs');
const { createServer } = require('node:http');
const { tmpdir } = require('node:os');
const { resolve, join } = require('node:path');

async function run(command, args) {
  await new Promise((resolveRun, reject) => {
    const child = spawn(command, args, { stdio: 'inherit', timeout: 60000, killSignal: 'SIGKILL' });
    child.on('error', reject);
    child.on('exit', (code, signal) => code === 0 ? resolveRun() :
      reject(new Error(`${command} exited with ${code}, signal ${signal}`)));
  });
}

async function smoke(agent, declarative) {
  const serviceName = declarative ? 'beacon-ci-smoke-declarative' : 'beacon-ci-smoke';
  const directory = mkdtempSync(join(tmpdir(), 'beacon-smoke-'));
  const exports = [];
  let traceparent;
  const server = createServer((request, response) => {
    if (request.url === '/beacon-smoke') {
      traceparent = request.headers.traceparent;
      response.end('ok');
    } else if (request.url === '/v1/traces' && request.method === 'POST') {
      const chunks = [];
      request.on('data', (chunk) => chunks.push(chunk));
      request.on('end', () => {
        exports.push({ type: request.headers['content-type'], body: Buffer.concat(chunks) });
        response.writeHead(200, { 'Content-Type': 'application/x-protobuf' });
        response.end();
      });
    } else {
      response.writeHead(404).end();
    }
  });
  try {
    await new Promise((resolveListen, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', resolveListen);
    });
    const endpoint = `http://127.0.0.1:${server.address().port}`;
    await run('javac', ['-d', directory, join(__dirname, 'fixtures/BeaconSmoke.java')]);
    const configFile = join(directory, 'config.yaml');
    if (declarative) {
      writeFileSync(configFile, `file_format: '1.2'
propagator:
  composite:
    - tracecontext:
resource:
  attributes:
    - name: service.name
      value: ${serviceName}
tracer_provider:
  processors:
    - batch:
        schedule_delay: 100
        exporter:
          otlp_http:
            endpoint: ${endpoint}/v1/traces
`);
    }
    await run('java', [
      `-javaagent:${agent}`, '-Dotel.service.name=beacon-ci-smoke',
      '-Dotel.traces.exporter=otlp', '-Dotel.metrics.exporter=none', '-Dotel.logs.exporter=none',
      '-Dotel.traces.sampler=always_on', '-Dotel.propagators=tracecontext',
      '-Dotel.exporter.otlp.protocol=http/protobuf', '-Dotel.exporter.otlp.compression=none',
      `-Dotel.exporter.otlp.traces.endpoint=${endpoint}/v1/traces`,
      ...(declarative ? [`-Dotel.config.file=${configFile}`] : []),
      '-Dotel.bsp.schedule.delay=100', '-cp', directory, 'BeaconSmoke', `${endpoint}/beacon-smoke`,
    ]);
    assert.match(traceparent || '', /^00-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$/);
    assert.equal(parseInt(traceparent.split('-')[3], 16) & 1, 1, 'Trace must be sampled');
    const traceId = Buffer.from(traceparent.split('-')[1], 'hex');
    assert(exports.some(({ type, body }) => type === 'application/x-protobuf' &&
      body.includes(traceId) && body.includes(Buffer.from(serviceName)) &&
      body.includes(Buffer.from('/beacon-smoke'))), 'Missing correlated HTTP span in OTLP export');
    const version = readFileSync(join(__dirname, '../version.properties'), 'utf8')
      .match(/^version=(.+)$/m)[1].trim();
    assert(exports.some(({ body }) =>
      body.includes(Buffer.from('telemetry.distro.name')) &&
      body.includes(Buffer.from('beacon-java-instrumentation')) &&
      body.includes(Buffer.from('telemetry.distro.version')) &&
      body.includes(Buffer.from(version)) &&
      body.includes(Buffer.from('telemetry.sdk.name')) &&
      body.includes(Buffer.from('opentelemetry'))), 'Missing Beacon distribution identity in OTLP export');
    console.log(`PASS (${declarative ? 'declarative' : 'flat'}): packaged Agent instruments HTTP, propagates context and exports OTLP traces with Beacon identity.`);
  } finally {
    server.closeAllConnections();
    await new Promise((done) => server.close(done));
    rmSync(directory, { recursive: true, force: true });
  }
}

async function main() {
  assert(process.argv[2], 'Usage: node beacon/scripts/agent-smoke.cjs <agent.jar>');
  const agent = resolve(process.argv[2]);
  assert(existsSync(agent), `Missing agent: ${agent}`);
  await smoke(agent, false);
  await smoke(agent, true);
}

main().catch((error) => { console.error(error); process.exitCode = 1; });

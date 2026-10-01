// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const {
  existsSync, mkdtempSync, readFileSync, rmSync,
} = require('node:fs');
const { get } = require('node:http');
const { tmpdir } = require('node:os');
const { join, resolve } = require('node:path');

const pause = (milliseconds) => new Promise((done) => setTimeout(done, milliseconds));

async function within(promise, timeout, message) {
  let timer;
  try {
    return await Promise.race([
      promise,
      new Promise((resolveValue, reject) => {
        timer = setTimeout(() => reject(new Error(message)), timeout);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

async function eventually(action, description, timeout = 30000) {
  const deadline = Date.now() + timeout;
  let lastError;
  while (Date.now() < deadline) {
    try {
      return await action();
    } catch (error) {
      lastError = error;
      await pause(200);
    }
  }
  throw new Error(`Timed out waiting for ${description}`, { cause: lastError });
}

async function request(port, path) {
  return new Promise((resolveRequest, reject) => {
    const call = get({ host: '127.0.0.1', port, path }, (response) => {
      const chunks = [];
      response.on('data', (chunk) => chunks.push(chunk));
      response.on('end', () => {
        const body = Buffer.concat(chunks).toString('utf8');
        if (response.statusCode !== 200) {
          reject(new Error(`${path} returned ${response.statusCode}: ${body}`));
          return;
        }
        try {
          resolveRequest(JSON.parse(body));
        } catch (error) {
          reject(new Error(`${path} did not return JSON: ${body}`, { cause: error }));
        }
      });
    });
    call.setTimeout(5000, () => call.destroy(new Error(`${path} timed out`)));
    call.on('error', reject);
  });
}

async function stop(child) {
  if (child.exitCode !== null || child.signalCode !== null) return;
  const exited = new Promise((done) => child.once('exit', done));
  child.kill('SIGTERM');
  try {
    await within(exited, 10000, 'Fixture shutdown timed out');
  } catch {
    if (child.exitCode === null && child.signalCode === null) {
      child.kill('SIGKILL');
      await exited;
    }
  }
}

async function main() {
  assert(process.argv[2] && process.argv[3],
    'Usage: node beacon/scripts/security-smoke.cjs <agent.jar> <fixture.jar>');
  const agent = resolve(process.argv[2]);
  const fixture = resolve(process.argv[3]);
  assert(existsSync(agent), `Missing agent: ${agent}`);
  assert(existsSync(fixture), `Missing fixture: ${fixture}`);

  const directory = mkdtempSync(join(tmpdir(), 'beacon-security-smoke-'));
  const output = join(directory, 'output');
  const java = process.env.JAVA_HOME ? join(process.env.JAVA_HOME, 'bin', 'java') : 'java';
  if (process.env.JAVA_HOME) assert(existsSync(java), `Missing Java launcher: ${java}`);

  let application;
  let completed = false;
  try {
    let startup = '';
    let settlePort;
    let rejectPort;
    const portReady = new Promise((resolvePort, rejectStartup) => {
      settlePort = resolvePort;
      rejectPort = rejectStartup;
    });
    application = spawn(java, [
      `-javaagent:${agent}`,
      '-Dotel.service.name=beacon-security-smoke',
      '-Dotel.traces.exporter=none',
      '-Dotel.metrics.exporter=none',
      '-Dotel.logs.exporter=none',
      '-jar', fixture,
      '--server.port=0',
    ], {
      env: {
        ...process.env,
        BEACON_SECURITY_ENABLED: 'true',
        BEACON_SECURITY_LOCAL_OUTPUT_ENABLED: 'true',
        BEACON_SECURITY_OUTPUT: output,
        BEACON_SECURITY_EVIDENCE_FILE: join(output, 'evidence.jsonl'),
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    const inspectStartup = (chunk, stream) => {
      stream.write(chunk);
      startup += chunk.toString('utf8');
      const match = startup.match(/Tomcat started on port\(s\): (\d+)/);
      if (match) settlePort(Number(match[1]));
    };
    application.stdout.on('data', (chunk) => inspectStartup(chunk, process.stdout));
    application.stderr.on('data', (chunk) => inspectStartup(chunk, process.stderr));
    application.once('error', rejectPort);
    application.once('exit', (code, signal) => {
      rejectPort(new Error(`Fixture exited before startup with ${code}, signal ${signal}`));
    });

    const port = await within(portReady, 45000, 'Fixture startup timed out');
    // Tomcat starts before this fixture's CommandLineRunner finishes creating its H2 schema.
    await pause(1000);
    assert.deepEqual(await request(port, '/health'), { status: 'ok' });
    assert.equal(
      (await eventually(
        () => request(port, '/api/sql/constant'),
        'fixture database initialization',
      )).operation,
      'constant-sql',
    );
    assert.equal((await request(port, '/api/sql?value=guest')).operation, 'dynamic-sql');
    assert.equal(
      (await request(port, '/api/sql/parameterized?value=guest')).operation,
      'parameterized-sql',
    );
    const findings = await eventually(() => {
      const value = JSON.parse(readFileSync(join(output, 'findings.json'), 'utf8'));
      assert.equal(value.findings.length, 1);
      return value;
    }, 'one dynamic-SQL finding and no prepared-statement finding');
    const finding = findings.findings[0];
    assert.equal(findings.schema_version, 1);
    assert.equal(findings.source, 'beacon_security');
    assert.equal(findings.identity.service['service.name'], 'beacon-security-smoke');
    assert.equal(finding.rule, 'sql_injection');
    assert.equal(finding.request.route, '/api/sql');
    assert.equal(finding.representative.event_name, 'beacon.security.finding');
    assert.equal(finding.representative.fingerprint_version, 1);
    assert.equal(finding.representative.application_id, findings.identity.application_id);

    const health = JSON.parse(readFileSync(join(output, 'health.json'), 'utf8'));
    assert.equal(health.collection_status, 'enabled');
    assert.equal(health.effective, true);
    assert.equal(health.delivery_loss, 0);
    assert.notEqual(health.version, 'development');
    const sbom = JSON.parse(readFileSync(join(output, 'application.cdx.json'), 'utf8'));
    assert.equal(sbom.bomFormat, 'CycloneDX');
    assert.ok(sbom.components.length > 0, 'Runtime SBOM must contain observed components');

    const evidence = readFileSync(join(output, 'evidence.jsonl'), 'utf8')
      .trim().split('\n').map((line) => JSON.parse(line));
    assert.equal(
      evidence.filter((event) => event.event_name === 'beacon.security.finding').length,
      1,
    );
    completed = true;
    console.log('PASS: embedded Beacon Security detects dynamic SQL, ignores parameterized SQL, and writes runtime SBOM diagnostics.');
  } finally {
    if (application) await stop(application);
    if (!completed) console.error(`Security smoke output: ${directory}`);
    else rmSync(directory, { recursive: true, force: true });
  }
}

main().catch((error) => { console.error(error); process.exitCode = 1; });

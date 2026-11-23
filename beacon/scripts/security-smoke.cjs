// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const {
  existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync,
} = require('node:fs');
const { createServer, get } = require('node:http');
const { tmpdir } = require('node:os');
const { join, resolve } = require('node:path');

const pause = (milliseconds) => new Promise((done) => setTimeout(done, milliseconds));

const siemFields = ['time', 'event_id', 'event_class', 'source', 'service', 'tenant_id',
  'actor', 'ip', 'action', 'target', 'target_type', 'outcome', 'status', 'severity', 'message'];

function securityPayload(line, tenant) {
  const envelope = JSON.parse(line);
  const payload = JSON.parse(envelope.message);
  const correlation = ['instance_id', 'trace_id', 'span_id', 'trace_flags'];
  assert.deepEqual(Object.keys(envelope), [...siemFields, ...correlation.filter(key => key in payload)]);
  assert.equal(envelope.instance_id, payload.instance_id);
  for (const key of correlation.filter(key => key in payload)) assert.equal(envelope[key], payload[key]);
  if ('trace_flags' in envelope) {
    assert(Number.isInteger(envelope.trace_flags));
    assert(envelope.trace_flags >= 0 && envelope.trace_flags <= 255);
  }
  for (const key of siemFields) assert.equal(typeof envelope[key], 'string');
  assert.equal(envelope.service, 'beacon-security-smoke');
  assert.equal(envelope.tenant_id, tenant);
  assert.equal(envelope.actor, '');
  assert.equal(envelope.ip, '');
  assert.equal(envelope.status, 'info');
  assert.equal(envelope.severity, 'informational');
  assert.equal(payload.schema_version, 2);
  assert.equal(envelope.source, payload.source);
  assert.equal(envelope.time, payload.observed_at);
  if (payload.event_name === 'beacon.security.finding') {
    assert(!Object.hasOwn(payload, 'server_span_id'));
    assert(!Object.hasOwn(payload, 'current_span_id'));
    if (payload.span_id) assert.match(payload.span_id, /^[0-9a-f]{16}$/);
    assert.equal(envelope.event_class, 'security_finding');
    assert.equal(envelope.event_id, payload.occurrence_id);
    assert.equal(envelope.action, payload.rule);
    assert.equal(envelope.target, payload.finding_id);
    assert.equal(envelope.target_type, 'finding');
    assert.equal(envelope.outcome, 'unknown');
  } else {
    assert.equal(payload.event_name, 'beacon.security.sbom.inventory');
    assert.equal(envelope.event_class, 'software_inventory_info');
    assert.equal(envelope.target_type, 'process');
    assert.equal(envelope.target, payload.instance_id);
    assert.equal(envelope.action, 'inventory_snapshot');
    assert.equal(envelope.outcome, 'success');
    assert.match(envelope.event_id, /^inventory-[0-9a-f]{64}$/);
  }
  return payload;
}

// Decode only the protobuf wire types needed to inspect actual OTLP log exports.
function protobufFields(bytes) {
  const fields = new Map();
  let offset = 0;
  const varint = () => {
    let value = 0;
    let shift = 0;
    let octet;
    do {
      assert(offset < bytes.length && shift < 70, 'Invalid protobuf varint');
      octet = bytes[offset++];
      value += (octet & 127) * (2 ** shift);
      shift += 7;
    } while (octet & 128);
    return value;
  };
  while (offset < bytes.length) {
    const tag = varint();
    const number = Math.floor(tag / 8);
    const wire = tag & 7;
    let value;
    if (wire === 0) value = varint();
    else if (wire === 2) {
      const length = varint();
      assert(offset + length <= bytes.length, 'Invalid protobuf length');
      value = bytes.subarray(offset, offset + length);
      offset += length;
    } else if (wire === 5) {
      assert(offset + 4 <= bytes.length, 'Truncated protobuf fixed32');
      value = bytes.readUInt32LE(offset);
      offset += 4;
    } else if (wire === 1) {
      offset += 8;
      assert(offset <= bytes.length, 'Truncated protobuf field');
      continue;
    } else throw new Error(`Unsupported protobuf wire type ${wire}`);
    if (!fields.has(number)) fields.set(number, []);
    fields.get(number).push(value);
  }
  return fields;
}

function otlpLogs(bytes, tenant) {
  const records = [];
  for (const resourceLogs of protobufFields(bytes).get(1) || []) {
    const resourceFields = protobufFields(resourceLogs);
    const resource = {};
    for (const entry of protobufFields(resourceFields.get(1)[0]).get(1) || []) {
      const kv = protobufFields(entry);
      const value = protobufFields(kv.get(2)[0]).get(1);
      if (value) resource[kv.get(1)[0].toString('utf8')] = value[0].toString('utf8');
    }
    for (const scopeLogs of resourceFields.get(2) || []) {
      const scope = protobufFields(scopeLogs);
      const name = protobufFields(scope.get(1)[0]).get(1)[0].toString('utf8');
      if (name !== 'io.beacon.security') continue;
      for (const log of scope.get(2) || []) {
        const fields = protobufFields(log);
        const body = protobufFields(fields.get(5)[0]).get(1)[0].toString('utf8');
        const payload = securityPayload(body, tenant);
        assert.equal(resource['service.name'], 'beacon-security-smoke');
        assert.equal(fields.get(2)[0], 9);
        if (payload.trace_id && payload.span_id) {
          assert.equal(fields.get(9)[0].toString('hex'), payload.trace_id);
          assert.equal(fields.get(10)[0].toString('hex'), payload.span_id);
          if ('trace_flags' in payload) assert.equal((fields.get(8)?.[0] || 0) & 255, payload.trace_flags);
        } else {
          assert(!fields.get(9));
          assert(!fields.get(10));
        }
        records.push({ body, payload });
      }
    }
  }
  return records;
}

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

async function verify(includeNoEvidence, tenant = 'default') {
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

  const exportEnvironment = { ...process.env };
  delete exportEnvironment.BEACON_SECURITY_EXPORT_NO_EVIDENCE_ENABLED;
  if (includeNoEvidence) exportEnvironment.BEACON_SECURITY_EXPORT_NO_EVIDENCE_ENABLED = 'true';

  let application;
  const received = [];
  const receiverErrors = [];
  const receiver = createServer((call, response) => {
    if (call.url !== '/v1/logs' || call.method !== 'POST') {
      response.writeHead(404).end();
      return;
    }
    const chunks = [];
    call.on('data', (chunk) => chunks.push(chunk));
    call.on('end', () => {
      try {
        assert.equal(call.headers['content-type'], 'application/x-protobuf');
        received.push(...otlpLogs(Buffer.concat(chunks), tenant));
        response.writeHead(200, { 'Content-Type': 'application/x-protobuf' }).end();
      } catch (error) {
        receiverErrors.push(error);
        response.writeHead(500).end();
      }
    });
  });
  let completed = false;
  try {
    await new Promise((done, reject) => {
      receiver.once('error', reject);
      receiver.listen(0, '127.0.0.1', done);
    });
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
      '-Dotel.logs.exporter=otlp',
      `-Dotel.resource.attributes=${tenant === 'default' ? '' : `tenant.id=${tenant}`}`,
      '-Dotel.exporter.otlp.logs.protocol=http/protobuf',
      '-Dotel.exporter.otlp.logs.compression=none',
      `-Dotel.exporter.otlp.logs.endpoint=http://127.0.0.1:${receiver.address().port}/v1/logs`,
      '-Dotel.blrp.schedule.delay=100',
      '-jar', fixture,
      '--server.port=0',
    ], {
      env: {
        ...exportEnvironment,
        BEACON_SECURITY_ENABLED: 'true',
        BEACON_SECURITY_ANALYSIS_SQL_DIALECT: 'ansi',
        BEACON_SECURITY_LOCAL_OUTPUT_ENABLED: 'true',
        BEACON_SECURITY_SBOM_REFRESH_SECONDS: '1',
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
    for (const value of ['guest', 'alice', "' OR '1'='1", 'guest']) {
      assert.equal((await request(port, `/api/sql?value=${encodeURIComponent(value)}`)).operation,
        'dynamic-sql');
    }
    assert.equal(
      (await request(port, '/api/sql/parameterized?value=guest')).operation,
      'parameterized-sql',
    );
    const findings = await eventually(() => {
      const value = JSON.parse(readFileSync(join(output, 'findings.json'), 'utf8'));
      assert.equal(value.findings.length, 1);
      assert.equal(value.findings[0].occurrences, 4);
      return value;
    }, 'one dynamic-SQL finding and no prepared-statement finding');
    const finding = findings.findings[0];
    assert.equal(findings.schema_version, 2);
    assert.equal(findings.source, 'beacon_security');
    assert.equal(findings.identity.service['service.name'], 'beacon-security-smoke');
    assert.equal(finding.rule, 'sql_injection');
    assert.deepEqual(finding.attack_evidence_counts, { unknown: 0, no_evidence: 3, suspected: 1 });
    assert.equal(finding.representative.attack_evidence.status, 'suspected');
    assert.equal(finding.representative.attack_evidence.outcome, 'not_assessed');
    assert.equal(finding.request.route, '/api/sql');
    assert.equal(finding.representative.event_name, 'beacon.security.finding');
    assert.equal(finding.representative.fingerprint_version, 1);
    assert.equal(finding.representative.instance_id, findings.identity.instance_id);
    assert.ok(findings.identity.instance_id);
    assert.ok(!Object.hasOwn(findings.identity, 'application_id'));
    assert.ok(!Object.hasOwn(finding.representative, 'application_id'));
    assert.ok(!Object.hasOwn(finding.representative, 'evidence_id'));
    assert.ok(!Object.hasOwn(finding.representative, 'occurrences_total'));
    if (finding.representative.component) {
      assert.ok(finding.representative.component.name);
      assert.ok(!Object.hasOwn(finding.representative.component, 'revision'));
    }

    const health = JSON.parse(readFileSync(join(output, 'health.json'), 'utf8'));
    assert.equal(health.collection_status, 'enabled');
    assert.equal(health.effective, true);
    assert.equal(health.delivery_loss, 0);
    assert.notEqual(health.version, 'development');
    const sbom = JSON.parse(readFileSync(join(output, 'application.cdx.json'), 'utf8'));
    assert.equal(sbom.bomFormat, 'CycloneDX');
    assert.ok(sbom.components.length > 0, 'Runtime SBOM must contain observed components');

    assert.equal((await request(port,
      `/api/sql/dynamic-prepared?value=${encodeURIComponent("' OR '1'='1")}`)).operation,
    'dynamic-prepared-sql');
    const evidence = await eventually(() => {
      const records = readFileSync(join(output, 'evidence.jsonl'), 'utf8')
        .trim().split('\n').map((line) => securityPayload(line, tenant));
      assert.equal(records.filter((event) => event.event_name === 'beacon.security.finding').length, includeNoEvidence ? 5 : 2);
      return records;
    }, 'request occurrences matching the export policy');
    const prepared = evidence.find((event) => event.event_name === 'beacon.security.finding'
      && event.request.route === '/api/sql/dynamic-prepared');
    assert.equal(prepared.attack_evidence.status, 'suspected');
    assert.ok(!Object.hasOwn(prepared.attack_evidence, 'outcome'));
    const occurrences = evidence.filter((event) => event.event_name === 'beacon.security.finding'
      && event.request.route === '/api/sql');
    const expectedOccurrences = includeNoEvidence ? 4 : 1;
    assert.equal(occurrences.length, expectedOccurrences);
    assert.equal(new Set(occurrences.map((event) => event.finding_id)).size, 1);
    assert.equal(new Set(occurrences.map((event) => event.occurrence_id)).size, expectedOccurrences);
    assert.equal(new Set(occurrences.map((event) => event.trace_id)).size, expectedOccurrences);
    assert(occurrences.every((event) => /^[0-9a-f]{32}$/.test(event.trace_id)));
    // Priority lanes deliberately permit delivery order to differ from request order.
    const ordinary = occurrences.filter((event) => event.attack_evidence.status === 'no_evidence');
    const attacks = occurrences.filter((event) => event.attack_evidence.status === 'suspected');
    assert.equal(ordinary.length, includeNoEvidence ? 3 : 0);
    assert.equal(ordinary.filter((event) => event.evidence_sampled).length, includeNoEvidence ? 1 : 0);
    assert.equal(attacks.length, 1);
    assert.equal(attacks[0].evidence_sampled, true);
    assert(occurrences.every((event) => !Object.hasOwn(event, 'execution_observation')));
    for (const route of ['file', 'lines']) {
      await request(port, `/api/coverage/${route}?name=sample.txt`);
    }
    await request(port, `/api/coverage/https?target=${encodeURIComponent('https://fixture.invalid/path')}`);
    const attackValue = encodeURIComponent("' OR '1'='1");
    await request(port, `/api/coverage/batch?value=${attackValue}`);
    await request(port, `/api/coverage/large-update?value=${attackValue}`);
    await request(port, '/api/coverage/cleared-batch?value=guest');
    await request(port, '/api/coverage/prepared-batch?value=guest');
    await request(port, '/api/coverage/async-timeout');
    await eventually(() => {
      const records = readFileSync(join(output, 'evidence.jsonl'), 'utf8')
        .trim().split('\n').map((line) => securityPayload(line, tenant));
      const covered = records.filter((event) => event.event_name === 'beacon.security.finding');
      for (const [route, rule] of [['file', 'path_traversal'], ['lines', 'path_traversal'],
        ['https', 'ssrf'], ['batch', 'sql_injection'], ['large-update', 'sql_injection']]) {
        assert(covered.some((event) => event.request.route === `/api/coverage/${route}` && event.rule === rule),
          `Missing coverage for ${route}`);
      }
      assert(!covered.some((event) => ['/api/coverage/cleared-batch', '/api/coverage/prepared-batch'].includes(event.request.route)),
        'Cleared batches and fixed parameter binding must not produce findings');
      const current = JSON.parse(readFileSync(join(output, 'health.json'), 'utf8'));
      assert.equal(current.active_requests, 0, 'HTTP async timeout must release its request lease');
    }, 'file, HTTPS, batch, large update, and async lifecycle coverage');
    await eventually(() => {
      assert.deepEqual(receiverErrors, []);
      const onlineFindings = received.filter(({ payload }) => payload.event_name === 'beacon.security.finding');
      const inventory = received.filter(({ payload }) => payload.event_name === 'beacon.security.sbom.inventory');
      assert(inventory.some(({ payload }) => payload.dependencies.length > 0));
      for (const record of evidence) {
        const online = onlineFindings.find(({ payload }) => payload.occurrence_id === record.occurrence_id);
        assert(online, `Missing OTLP occurrence ${record.occurrence_id}`);
        assert.deepEqual(online.payload, record);
      }
      if (!includeNoEvidence) {
        assert(onlineFindings.every(({ payload }) => payload.attack_evidence.status !== 'no_evidence'));
      }
      const jsonl = readFileSync(join(output, 'evidence.jsonl'), 'utf8').trim().split('\n');
      const onlineBodies = new Set(onlineFindings.map(({ body }) => body));
      assert(jsonl.every((line) => onlineBodies.has(line)), 'JSONL and OTLP must retain identical envelopes');
    }, 'real OTLP findings, dependency inventory, and identical JSONL envelopes');
    if (process.env.BEACON_SECURITY_SMOKE_CAPTURE) {
      const mode = includeNoEvidence ? 'enabled' : 'default';
      writeFileSync(`${process.env.BEACON_SECURITY_SMOKE_CAPTURE}-${mode}.jsonl`,
        `${received.map(({ body }) => body).join('\n')}\n`);
    }
    completed = true;
    console.log(`PASS: per-request correlation, evidence upgrades, ordinary SQL classification, parameter binding, and runtime SBOM (no-evidence export: ${includeNoEvidence ? 'enabled' : 'default-disabled'}).`);
  } finally {
    if (application) await stop(application);
    await new Promise((done) => receiver.close(done));
    if (!completed) console.error(`Security smoke output: ${directory}`);
    else rmSync(directory, { recursive: true, force: true });
  }
}

async function main() {
  await verify(false);
  await verify(true, 'smoke-tenant');
}

main().catch((error) => { console.error(error); process.exitCode = 1; });

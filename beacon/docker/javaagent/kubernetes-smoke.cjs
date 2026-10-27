// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const { readFileSync } = require('node:fs');
const { join } = require('node:path');

const [context, image, version, digest] = process.argv.slice(2);
assert(context && image && version && digest,
  'Usage: node kubernetes-smoke.cjs <context> <image> <X.Y.Z> <agent-sha256>');
assert.match(version, /^\d+\.\d+\.\d+$/);
assert.match(digest, /^[0-9a-f]{64}$/);
const namespace = `beacon-java-image-${Date.now().toString(36)}-${process.pid}`;
const pythonImage = process.env.BEACON_K8S_PYTHON_IMAGE || 'python:3.12-slim';
const javaImage = process.env.BEACON_K8S_JAVA_IMAGE || 'eclipse-temurin:21-jdk';
const namespaceArgs = ['--context', context, '--namespace', namespace];
let created = false;

function kubectl(args, input, allowFailure = false) {
  const result = spawnSync('kubectl', [...namespaceArgs, ...args], {
    encoding: 'utf8', input, timeout: 240000, maxBuffer: 4 * 1024 * 1024,
  });
  if (!allowFailure && (result.error || result.status !== 0)) {
    throw new Error(`kubectl ${args.join(' ')}: ${result.error || result.stderr || result.stdout}`);
  }
  return result.stdout || '';
}

const receiver = `
import json
from http.server import BaseHTTPRequestHandler, HTTPServer

traceparent = None
correlated = False
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        global traceparent
        if self.path == '/beacon-smoke':
            traceparent = self.headers.get('traceparent')
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'ok')
        elif self.path == '/result':
            self.send_response(200)
            self.end_headers()
            self.wfile.write(json.dumps({'correlated': correlated, 'traceparent': traceparent}).encode())
        else:
            self.send_error(404)
    def do_POST(self):
        global correlated
        body = self.rfile.read(int(self.headers.get('content-length', '0')))
        if self.path != '/v1/traces':
            self.send_error(404)
            return
        if traceparent:
            fields = traceparent.split('-')
            correlated = (len(fields) == 4 and len(fields[1]) == 32 and
                bytes.fromhex(fields[1]) in body and b'beacon-kubernetes-smoke' in body and
                b'/beacon-smoke' in body)
            if correlated:
                print('PASS: correlated OTLP HTTP span received', flush=True)
        self.send_response(200)
        self.send_header('Content-Type', 'application/x-protobuf')
        self.end_headers()
HTTPServer(('0.0.0.0', 4318), Handler).serve_forever()
`;

const restricted = {
  runAsNonRoot: true, runAsUser: 65532, runAsGroup: 65532,
  allowPrivilegeEscalation: false, readOnlyRootFilesystem: true,
  capabilities: { drop: ['ALL'] }, seccompProfile: { type: 'RuntimeDefault' },
};
const resources = {
  requests: { cpu: '50m', memory: '128Mi' }, limits: { cpu: '1', memory: '512Mi' },
};
const fixture = { name: 'fixture', mountPath: '/fixture', readOnly: true };
const objects = [
  { apiVersion: 'v1', kind: 'ConfigMap', metadata: { name: 'fixture' }, data: {
    'receiver.py': receiver,
    'BeaconSmoke.java': readFileSync(join(__dirname, '../../scripts/fixtures/BeaconSmoke.java'), 'utf8'),
  } },
  { apiVersion: 'v1', kind: 'Service', metadata: { name: 'receiver' }, spec: {
    selector: { app: 'beacon-image-receiver' }, ports: [{ port: 4318, targetPort: 4318 }],
  } },
  { apiVersion: 'apps/v1', kind: 'Deployment', metadata: { name: 'receiver' }, spec: {
    replicas: 1, selector: { matchLabels: { app: 'beacon-image-receiver' } }, template: {
      metadata: { labels: { app: 'beacon-image-receiver' } }, spec: {
        automountServiceAccountToken: false,
        containers: [{ name: 'receiver', image: pythonImage, command: ['python', '-u', '/fixture/receiver.py'],
          securityContext: restricted, resources, volumeMounts: [fixture],
          readinessProbe: { tcpSocket: { port: 4318 }, initialDelaySeconds: 1, periodSeconds: 2 },
        }], volumes: [{ name: 'fixture', configMap: { name: 'fixture' } }],
      },
    },
  } },
  { apiVersion: 'batch/v1', kind: 'Job', metadata: { name: 'application' }, spec: {
    backoffLimit: 0, activeDeadlineSeconds: 180, template: { spec: {
      restartPolicy: 'Never', automountServiceAccountToken: false,
      securityContext: { fsGroup: 65532 },
      initContainers: [{ name: 'beacon-javaagent', image, imagePullPolicy: 'IfNotPresent',
        command: ['sh', '-ec',
          `cp /javaagent.jar /beacon/javaagent.jar; echo '${digest}  /beacon/javaagent.jar' | sha256sum -c -`],
        securityContext: restricted,
        resources: { requests: { cpu: '10m', memory: '16Mi' }, limits: { memory: '64Mi' } },
        volumeMounts: [{ name: 'agent', mountPath: '/beacon' }],
      }],
      containers: [{ name: 'application', image: javaImage,
        command: ['sh', '-ec',
          'env -u JAVA_TOOL_OPTIONS javac -d /tmp /fixture/BeaconSmoke.java; ' +
          'exec java -cp /tmp BeaconSmoke http://receiver:4318/beacon-smoke'],
        securityContext: restricted, resources,
        env: [
          ['JAVA_TOOL_OPTIONS', '-javaagent:/opt/beacon/javaagent.jar'],
          ['OTEL_SERVICE_NAME', 'beacon-kubernetes-smoke'],
          ['OTEL_TRACES_EXPORTER', 'otlp'], ['OTEL_METRICS_EXPORTER', 'none'],
          ['OTEL_LOGS_EXPORTER', 'none'], ['OTEL_TRACES_SAMPLER', 'always_on'],
          ['OTEL_PROPAGATORS', 'tracecontext'], ['OTEL_EXPORTER_OTLP_PROTOCOL', 'http/protobuf'],
          ['OTEL_EXPORTER_OTLP_COMPRESSION', 'none'],
          ['OTEL_EXPORTER_OTLP_ENDPOINT', 'http://receiver:4318'],
          ['OTEL_BSP_SCHEDULE_DELAY', '100'], ['BEACON_SECURITY_ENABLED', 'false'],
        ].map(([name, value]) => ({ name, value })),
        volumeMounts: [fixture, { name: 'agent', mountPath: '/opt/beacon', readOnly: true },
          { name: 'tmp', mountPath: '/tmp' }],
      }],
      volumes: [{ name: 'agent', emptyDir: {} }, { name: 'tmp', emptyDir: {} },
        { name: 'fixture', configMap: { name: 'fixture' } }],
    } },
  } },
];

try {
  console.log(`Testing ${image} on context ${context}, namespace ${namespace}`);
  kubectl(['create', 'namespace', namespace]);
  created = true;
  // Do not create the application until the in-cluster OTLP receiver is ready.
  kubectl(['apply', '-f', '-'], JSON.stringify({ apiVersion: 'v1', kind: 'List', items: objects.slice(0, 3) }));
  kubectl(['rollout', 'status', 'deployment/receiver', '--timeout=180s']);
  kubectl(['apply', '-f', '-'], JSON.stringify(objects[3]));
  kubectl(['wait', '--for=condition=complete', 'job/application', '--timeout=200s']);
  const logs = kubectl(['logs', 'job/application', '-c', 'application']);
  process.stdout.write(logs);
  assert(logs.includes(`version: ${version}`), 'Application did not load the expected Beacon version');
  const copyLogs = kubectl(['logs', 'job/application', '-c', 'beacon-javaagent']);
  assert(copyLogs.includes('/beacon/javaagent.jar: OK'), 'Init-container copy has a different digest');
  const result = JSON.parse(kubectl(['exec', 'deployment/receiver', '--', 'python', '-c',
    'import urllib.request; print(urllib.request.urlopen("http://127.0.0.1:4318/result").read().decode())']));
  assert.equal(result.correlated, true, 'No correlated OTLP HTTP span received');
  assert.match(result.traceparent, /^00-[0-9a-f]{32}-[0-9a-f]{16}-01$/);
  console.log(`PASS: Kubernetes initContainer, SHA-256, Beacon ${version}, non-root read-only application and correlated OTLP export.`);
} catch (error) {
  if (created) {
    process.stderr.write(kubectl(['get', 'pods', '-o', 'wide'], undefined, true));
    process.stderr.write(kubectl(['describe', 'pods'], undefined, true));
    process.stderr.write(kubectl(['logs', 'job/application', '--all-containers=true'], undefined, true));
  }
  console.error(error);
  process.exitCode = 1;
} finally {
  if (created) {
    console.log(kubectl(['delete', 'namespace', namespace, '--wait=false']));
  }
}

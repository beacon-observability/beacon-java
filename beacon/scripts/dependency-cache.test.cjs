// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

const assert = require('node:assert/strict');
const { execFile } = require('node:child_process');
const { mkdtempSync, writeFileSync, mkdirSync, rmSync } = require('node:fs');
const { createServer } = require('node:http');
const { tmpdir } = require('node:os');
const { resolve } = require('node:path');
const { promisify } = require('node:util');
const { test } = require('node:test');

const root = resolve(__dirname, '../..');
const execute = promisify(execFile);

test('dependency warmer downloads JARs for offline reuse without building project artifacts', async (t) => {
  const fixture = mkdtempSync(resolve(tmpdir(), 'beacon-dependency-cache-'));
  t.after(() => rmSync(fixture, { recursive: true, force: true }));
  const group = `beacon.fixture.${fixture.split('-').at(-1).toLowerCase()}`;
  const requests = [];
  const server = createServer((request, response) => {
    requests.push(request.url);
    const match = request.url.match(/\/([^/]+)\/([12]\.0)\/\1-\2\.(pom|jar)$/);
    if (!match || (match[1] === 'missing' && match[3] === 'jar')) {
      response.writeHead(404).end();
      return;
    }
    const [, artifact, version, extension] = match;
    const content = extension === 'pom'
      ? Buffer.from(`<project><modelVersion>4.0.0</modelVersion><groupId>${group}</groupId>`
        + `<artifactId>${artifact}</artifactId><version>${version}</version></project>`)
      : Buffer.from('UEsFBgAAAAAAAAAAAAAAAAAAAAAAAA==', 'base64'); // Empty ZIP/JAR.
    response.writeHead(200, { 'Content-Length': content.length });
    response.end(request.method === 'HEAD' ? undefined : content);
  });
  await new Promise((done) => server.listen(0, '127.0.0.1', done));
  t.after(() => { if (server.listening) server.close(); });
  const repository = `http://127.0.0.1:${server.address().port}`;
  writeFileSync(resolve(fixture, 'settings.gradle'),
    "rootProject.name = 'cache-fixture'\ninclude 'producer', 'consumer'\n");
  writeFileSync(resolve(fixture, 'build.gradle'), '');
  for (const name of ['producer', 'consumer']) {
    mkdirSync(resolve(fixture, name));
    writeFileSync(resolve(fixture, name, 'build.gradle'), `
plugins { id 'java-library' }
repositories { maven { url = uri('${repository}'); allowInsecureProtocol = true } }
sourceSets { integrationTest }
configurations { unusedDiagnostic { canBeResolved = true } }
dependencies {
  implementation '${group}:compile:1.0'
  runtimeOnly '${group}:runtime:' + (project.hasProperty('testLatestDeps') ? '2.0' : '1.0')
  annotationProcessor '${group}:processor:1.0'
  integrationTestImplementation '${group}:integration:1.0'
  unusedDiagnostic 'invalid.example:unrelated:0'
  if (project.hasProperty('missingArtifact')) runtimeOnly '${group}:missing:1.0'
  ${name === 'consumer' ? "implementation project(':producer')" : ''}
}
tasks.withType(JavaCompile).configureEach { doFirst { throw new GradleException('Must not compile') } }
tasks.withType(Test).configureEach { doFirst { throw new GradleException('Must not run tests') } }
tasks.withType(Jar).configureEach { doFirst { throw new GradleException('Must not build JARs') } }
`);
  }
  const args = ['-p', fixture, 'warmBeaconTestDependencies',
    '-I', resolve(root, 'beacon/testing/warm-dependencies.init.gradle'),
    '--no-configuration-cache', '--console=plain', '--max-workers=2'];
  async function warm(extra = []) {
    const result = await execute(resolve(root, 'gradlew'), [...args, ...extra], {
      cwd: fixture, timeout: 0, maxBuffer: 4 * 1024 * 1024,
    });
    assert.match(result.stdout, /Warmed 4 external artifacts/);
    assert.doesNotMatch(result.stdout, /> Task :(?:producer|consumer):(?:compile|test|jar)/);
    return result;
  }
  await warm();
  for (const artifact of ['compile', 'runtime', 'processor', 'integration']) {
    assert(requests.some((url) => url.endsWith(`/${artifact}-1.0.jar`)), `Missing JAR: ${artifact}`);
  }
  await warm(['-PtestLatestDeps=true']);
  assert(requests.some((url) => url.endsWith('/runtime-2.0.jar')));
  assert(!requests.some((url) => url.includes('unrelated')));
  await assert.rejects(() => warm(['-PmissingArtifact=true']), /missing-1.0.jar/);
  await new Promise((done) => server.close(done));
  await warm(['--offline']);
  await warm(['--offline', '-PtestLatestDeps=true']);
});

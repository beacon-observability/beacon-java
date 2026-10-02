// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { test } = require('node:test');

const repository = path.resolve(__dirname, '../..');

test('Beacon packaging keeps product identity separate from upstream versions', () => {
  const fixture = fs.mkdtempSync(path.join(os.tmpdir(), 'beacon-packaging-'));
  try {
    fs.mkdirSync(path.join(fixture, 'beacon'));
    for (const name of ['agent.gradle.kts', 'upstream.lock.json', 'security-spec.properties']) {
      fs.copyFileSync(path.join(repository, 'beacon', name), path.join(fixture, 'beacon', name));
    }
    fs.writeFileSync(path.join(fixture, 'settings.gradle.kts'), 'rootProject.name = "packaging-test"\n');
    const build = `
import org.gradle.jvm.tasks.Jar
plugins { java }
version = "2.30.2"
tasks.register<Jar>("shadowJar") {
  archiveBaseName.set("opentelemetry-javaagent")
  manifest.attributes("Premain-Class" to "io.opentelemetry.javaagent.OpenTelemetryAgent")
}
apply(from = "beacon/agent.gradle.kts")
check(version == "2.30.2") { "Beacon must not overwrite upstream project versions" }
`;
    fs.writeFileSync(path.join(fixture, 'build.gradle.kts'), build);
    const run = (...tasks) => {
      const result = spawnSync(path.join(repository, 'gradlew'), [
        '-p', fixture, '--no-daemon', '--console=plain', '--configuration-cache', ...tasks,
      ], { cwd: repository, encoding: 'utf8', maxBuffer: 8 * 1024 * 1024 });
      if (result.error) throw result.error;
      return result;
    };
    for (const version of ['0.1.0-SNAPSHOT', '1.2.3', '1.2.3-rc.1']) {
      fs.writeFileSync(path.join(fixture, 'beacon/version.properties'), `version=${version}\n`);
      const result = run('assemble', 'check');
      assert.equal(result.status, 0, result.stdout + result.stderr);
      assert.match(result.stdout, /:verifyBeaconAgent/);
      assert.ok(fs.existsSync(path.join(fixture, `build/libs/beacon-javaagent-${version}.jar`)));
    }
    const cached = run('assemble', 'check');
    assert.equal(cached.status, 0, cached.stdout + cached.stderr);
    assert.match(cached.stdout, /Reusing configuration cache/);
    fs.writeFileSync(path.join(fixture, 'beacon/version.properties'), 'version=../unsafe\n');
    const invalid = run('help');
    assert.notEqual(invalid.status, 0);
    assert.match(invalid.stdout + invalid.stderr, /Invalid Beacon version/);

    fs.writeFileSync(path.join(fixture, 'beacon/version.properties'), 'version=1.2.3\n');
    fs.writeFileSync(path.join(fixture, 'build.gradle.kts'), build + `
tasks.named<Jar>("shadowJar") {
  manifest.attributes("Implementation-Version" to "wrong")
}
`);
    const wrongManifest = run('check');
    assert.notEqual(wrongManifest.status, 0);
    assert.match(wrongManifest.stdout + wrongManifest.stderr, /Incorrect agent manifest attribute/);
  } finally {
    fs.rmSync(fixture, { recursive: true, force: true });
  }
});

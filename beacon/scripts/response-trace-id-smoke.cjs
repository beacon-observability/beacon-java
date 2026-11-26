/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

'use strict';

const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

async function main() {
  if (!process.argv[2]) throw new Error('Usage: node beacon/scripts/response-trace-id-smoke.cjs <agent.jar>');
  const agent = path.resolve(process.argv[2]);
  await fs.access(agent);
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'response-trace-id-'));
  const javaHome = process.env.JAVA_HOME;
  const bin = name => javaHome ? path.join(javaHome, 'bin', name) : name;
  const run = (command, args) => {
    const result = spawnSync(command, args, { stdio: 'inherit', timeout: 600000 });
    if (result.error) throw result.error;
    if (result.status !== 0) throw new Error(command + ' exited ' + result.status);
  };
  const download = async coordinate => {
    const target = path.join(dir, path.basename(coordinate));
    const response = await fetch('https://repo.maven.apache.org/maven2/' + coordinate);
    if (!response.ok) throw new Error('Download failed: ' + coordinate + ' ' + response.status);
    await fs.writeFile(target, Buffer.from(await response.arrayBuffer()));
    return target;
  };
  try {
    const netty = await download('io/netty/netty-all/4.1.0.Final/netty-all-4.1.0.Final.jar');
    const fixture = path.resolve(__dirname, '../testing/response-trace-id/src/test/java');
    for (const version of ['9.0.111', '10.1.48']) {
      const tomcat = await download('org/apache/tomcat/embed/tomcat-embed-core/' + version +
          '/tomcat-embed-core-' + version + '.jar');
      const annotations = await download('org/apache/tomcat/tomcat-annotations-api/' + version +
          '/tomcat-annotations-api-' + version + '.jar');
      const classes = path.join(dir, version);
      await fs.mkdir(classes);
      const dependencies = [netty, tomcat, annotations].join(path.delimiter);
      run(bin('javac'), ['--release', '11', '-cp', dependencies, '-d', classes,
        path.join(fixture, 'ResponseTraceIdServer.java'),
        path.join(fixture, 'ResponseTraceIdAcceptance.java')]);
      run(bin('java'), ['-cp', [classes, dependencies].join(path.delimiter),
        'ResponseTraceIdAcceptance', agent]);
    }
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
}

main().catch(error => { console.error(error); process.exitCode = 1; });

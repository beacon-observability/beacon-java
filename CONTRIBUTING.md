# Contributing Guide

Beacon Java features, bugs, and pull requests are handled in this repository. Pull requests target `main`. For improvements that apply to general OpenTelemetry behavior, first document the reproduction and impact here, then follow the upstream contribution process.

## Development setup

Use a full Git clone and JDK 21, and run the following commands from the repository root. Configuring a remote alone does not fetch history or change the GitHub default branch.

```bash
java -version
./gradlew :javaagent:assemble
```

The complete agent artifact is `javaagent/build/libs/beacon-javaagent-<Beacon-version>.jar`. The product version is defined exclusively by [beacon/version.properties](beacon/version.properties). `assemble` also validates the artifact name, Manifest product identity, and embedded upstream provenance. It does not replace functional testing or formal release acceptance.

The [Beacon packaging configuration](beacon/agent.gradle.kts) customizes only the complete agent's file name, Manifest, and provenance records. It does not replace upstream module versions, Maven coordinates, or Java package names. [version.gradle.kts](version.gradle.kts) continues to manage inherited module build versions, while the official OTel source is recorded separately in the [baseline file](beacon/upstream.lock.json). Internal helper JARs such as `base` and `dontuse` are not Beacon installation packages.

Do not treat official Sonatype snapshots as Beacon snapshots. Beacon does not currently provide a snapshot publication channel.

## Changes and testing

- Make native instrumentation changes in the corresponding upstream module, preserving the existing layout, package names, and licenses.
- Submit implementation and regression tests in the same pull request, and describe user-visible impact, configuration changes, and compatibility scope.
- Regular feature pull requests may organize commits according to team conventions. Upstream synchronization pull requests must preserve upstream ancestry.
- Record user-visible changes under `Unreleased` in the [Beacon Changelog](beacon/CHANGELOG.md). Keep implementation details and test evidence in the pull request and CI rather than maintaining a separate delta ledger. Breaking changes must include migration guidance.
- See the separately maintained [Beacon contributors list](beacon/CONTRIBUTORS.md). Merging upstream commits does not automatically list their authors as Beacon-specific contributors.
- The root [CHANGELOG.md](CHANGELOG.md) retains the upstream changelog. The Beacon changelog does not duplicate every upstream change. It is maintained manually and does not depend on upstream tag automation.

## Technical references

- [Code style](docs/contributing/style-guide.md)
- [Running tests](docs/contributing/running-tests.md)
- [Writing instrumentation](docs/contributing/writing-instrumentation.md)
- [Agent structure](docs/contributing/javaagent-structure.md)
- [Muzzle compatibility checks](docs/contributing/muzzle.md)
- [Debugging](docs/contributing/debugging.md)
- [IntelliJ setup](docs/contributing/intellij-setup-and-troubleshooting.md)

These technical documents are maintained with the adopted source tree. Do not assume that their upstream release destinations, organization permissions, or bot behavior are available to Beacon.

## Maintainer tool verification

The upstream tag-fetching script depends only on Bash and Git. After changing it, run the following tests, which additionally require Node.js 18 or later:

```bash
bash -n beacon/scripts/fetch-upstream-tag.sh
node --test beacon/scripts/fetch-upstream-tag.test.cjs
node --test beacon/scripts/ci-plan.test.cjs beacon/scripts/ci-workflow.test.cjs
```

These script tests use temporary local Git repositories only. They do not access the network, merge source, or publish releases.

After changing the product packaging configuration, run:

```bash
node --test beacon/scripts/agent-packaging.test.cjs
```

This test uses the repository Gradle Wrapper to execute the real packaging configuration in a temporary minimal project. It validates the product version, file name, Manifest, and rejection of invalid input. The first run may download Gradle. It does not build the complete agent and cannot replace `:javaagent:assemble`.

After building the complete agent, run the Docker-free HTTP instrumentation and OTLP trace export smoke test:

```bash
node beacon/scripts/agent-smoke.cjs javaagent/build/libs/beacon-javaagent-<Beacon-version>.jar
```

Replace the placeholder with the version in `beacon/version.properties`. See the [CI guide](beacon/CI.md) for CI tiers and manual extended validation.

## Launch and releases

Complete the [CI checklist](beacon/CI.md) before the initial GitHub launch, and follow the [release process](beacon/RELEASING.md) for formal releases. See the [CI guide](beacon/CI.md) for `main` branch protection and Beacon maintainers; do not reuse the upstream organization's CODEOWNERS configuration.

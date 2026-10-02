# Beacon Java Development Guide

This repository maintains the complete OpenTelemetry Java Instrumentation source tree together with Beacon enhancements. The main product entry point is [beacon-observability/beacon](https://github.com/beacon-observability/beacon).

## Repository layout

Links below are relative to this file; run all commands from the repository root.

| Location | Purpose |
| --- | --- |
| [instrumentation](../instrumentation/) | Native instrumentation implementations and tests |
| [javaagent](../javaagent/) | Agent assembly |
| [javaagent-tooling](../javaagent-tooling/) | Instrumentation tooling and loading mechanisms |
| [beacon](./) | Product packaging configuration, version, documentation, baseline, and tools; not a standalone Gradle module |
| [workflows](../.github/workflows/) | Build, test, and inherited automation definitions |

## Maintenance resources

- [Pinned provenance and adopted baseline](upstream.lock.json): the import record is historical fact. The upstream fields identify the currently adopted official release ancestor; they do not imply that the code is identical to upstream.
- [Upstream synchronization](UPSTREAM.md): initial setup, pinning a target commit, and synchronization steps.
- [Beacon Changelog](CHANGELOG.md): product version changes, upstream upgrades, and compatibility notes. Detailed code differences and test evidence belong in Git and pull requests.
- [Beacon contributors](CONTRIBUTORS.md): distinguishes Beacon downstream contributions from inherited upstream authors while retaining traceable commit evidence.
- [Product version](version.properties) and [packaging configuration](agent.gradle.kts): define the complete agent's product identity without rewriting upstream dependency versions.
- [Contributing guide](../CONTRIBUTING.md): build, development, and testing instructions.
- [CI status and launch checklist](CI.md): identifies which automation can run and which automation has not yet been adapted.
- [Release process](RELEASING.md): versioning, artifact validation, and rollback.

The development branch is `main` and continues from the imported downstream enhancement history. Do not replace the current code with another repository's `main`. Custom upstream references do not appear under `refs/upstream-tags/*` merely by cloning the Beacon repository; configure and fetch them explicitly according to the synchronization guide.

Upstream package names, repository layout, and licenses are retained. Make required native instrumentation changes in the corresponding modules. Prefer Extensions for independently implementable capabilities, and do not perform repository-wide replacement of upstream identifiers solely for product branding.

## Currently inherited custom capabilities

The following are source entry points, not support commitments that have completed Beacon release acceptance:

| Capability | Entry point |
| --- | --- |
| Legacy JDBC configuration compatibility | [jdbc](../instrumentation/jdbc/) |
| Experimental JFR Profiling and DataKit export | [profiling](../instrumentation/profiling/) |
| Spring AI model calls | [spring-ai-1.0](../instrumentation/spring/spring-ai-1.0/) |
| Spring AI Alibaba Agent and tool calls | [spring-ai-alibaba-agent-1.0](../instrumentation/spring/spring-ai-alibaba-agent-1.0/) |

HSF instrumentation has been temporarily removed because its SDK dependency was available only as a developer-local artifact and no artifact source is available to CI. The current agent does not provide HSF auto-instrumentation. The historical implementation remains in Git history; restoring it requires a reliable dependency source plus build and compatibility validation.

## Beacon Security extension

[Beacon Security](../extensions/security/) is implemented as an opt-in extension embedded in the
complete Beacon Java agent. It is not a separate repository, release line, or application-facing
JAR. Its runtime data-flow observation, finding events, local diagnostic snapshots, and runtime
SBOM have local test evidence, but have not yet completed public release acceptance. Security is
disabled by default; applications continue to use one `-javaagent` when it is enabled.

## Profiling extension boundary

The intended direction is an independent implementation embedded by default. In a future change, the JFR collection and export core and the OTel lifecycle adapter will move to `extensions/profiling/core/` and `extensions/profiling/agent-extension/` in this repository. These directories do not exist yet and are not current build entry points.

After migration, the same extension will be embedded in the complete Beacon agent, so users will still need only one `-javaagent`. A standalone extension artifact may be offered later if there is a concrete external-use requirement. Initially, the extension will share the Beacon release version and cadence rather than using a separate repository or version cycle. The migration must remove the old internally compiled entry point to prevent duplicate collection and must validate SPI behavior, dependency isolation, multi-release JAR behavior, and compatibility with the adopted OTel version. The current Profiling code is not moved as part of this release.

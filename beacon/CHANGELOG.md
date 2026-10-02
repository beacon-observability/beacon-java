# Beacon Java Changelog

This file records Beacon product changes only. The root [CHANGELOG.md](../CHANGELOG.md) retains the upstream changelog. The OTel tag and full commit are recorded in the [baseline file](upstream.lock.json).

## Unreleased

## Version 1.1.0 (2026-10-02)

This release adds Beacon Security to the complete Beacon Java agent as an opt-in capability. The
publication scope is the versioned complete Agent JAR; it does not include a standalone Security
extension JAR or a Beacon-owned container image.

### Beacon Security

- Migrated the Java runtime data-flow and runtime SBOM implementation into the internal
  `extensions/security` module and embedded it in the complete Beacon Java agent. Applications use
  one Agent JAR, while Security remains disabled by default and shares OpenTelemetry resource
  identity and OTLP Logs delivery.
- Established the initial `beacon.security.*` configuration and `beacon.security.*` event contract
  without legacy compatibility aliases, added local diagnostic output as an explicit opt-in, and
  added a Boot 2 end-to-end smoke test plus a native Kubernetes initContainer deployment example.
- Pinned the language-neutral
  [Beacon Security specification](https://github.com/beacon-observability/beacon-security-spec) by
  immutable commit and embedded its repository, revision, schema version, and fingerprint version
  in the complete Agent artifact provenance.
- Published Security as part of `beacon-javaagent-1.1.0.jar`, disabled by default. The Kubernetes
  initContainer manifest is a deployment example and does not imply publication of a Beacon-owned
  container image.

### Engineering and release

- Added Beacon-owned release preparation and controlled publication workflows. A formal release is
  bound to a successful full Beacon CI run for the exact source commit, promotes one tested Agent
  candidate without rebuilding it, and publishes its checksum, SPDX SBOM, provenance, licenses,
  notices, and GitHub build-provenance attestations.
- Added a repository-owned Spring Boot 2 fixture and made the packaged-agent CI path verify dynamic
  SQL detection, prepared-statement suppression, runtime SBOM output, and delivery health.

## Version 1.0.0 (2026-09-28)

This is the first public stable release of Beacon Java. The actual support scope is defined by acceptance records bound to the artifact digest.

### Removed capabilities

- Temporarily removed the Taobao HSF Javaagent and library modules together with the `hsf-sdk` dependency, eliminating the build's dependency on developer-local artifacts. The current agent no longer provides HSF auto-instrumentation, and the former `otel.instrumentation.hsf.enabled` and `otel.instrumentation.hsf-client.enabled` switches cannot restore it. Users who depend on HSF trace collection should migrate only after support has been restored and validated. The historical source remains in Git history.

### Upstream synchronization

- Integrated official OTel Java Instrumentation [v2.31.1](https://github.com/open-telemetry/opentelemetry-java-instrumentation/releases/tag/v2.31.1), pinned to commit `8ad06a082e051f366f19c16ad95a7b68edf30afd`, together with its SDK 1.65.0, dependency constraints, and Gradle Wrapper.
- Retained downstream implementations for legacy JDBC configuration compatibility, Profiling, Spring AI, and Alibaba Agent, together with Beacon packaging and workflow isolation. HSF is temporarily removed as described above. Beacon product version `1.0.0` is the first public stable release.
- Upstream 2.31.x includes unstable API changes and configuration deprecations. Review the root [upstream changelog](../CHANGELOG.md) when upgrading. Version 2.31.1 fixes the stable semantic-convention API compile dependency for Spring Boot autoconfigure and starter.
- Corrected YAML description syntax and default-value representation in the Profiling metadata, and documented the actual default file export path. Runtime configuration and behavior are unchanged.

### Engineering and release

- Migrated the source repository to `beacon-observability/beacon-java` and updated Beacon CI repository-isolation conditions, project entry links, and product vendor identity.
- Added a dedicated Beacon CI entry point. Regular pull requests use a reduced JDK matrix while retaining all test partitions and both Indy modes; changes to shared core code or the upstream baseline automatically expand validation. Heavy compatibility testing is available through a manual entry point, and upstream pull-request image builds no longer run automatically in Beacon. Independent security checks remain enabled, and the packaged agent now has HTTP, TraceContext, and OTLP trace export smoke tests.
- Established `main` as the product development branch while retaining full upstream history and existing downstream enhancements.
- Introduced independent product versioning, beginning with public stable release `1.0.0`.
- Named the complete agent `beacon-javaagent-<Beacon-version>.jar`. Its Manifest records the Beacon version, module build version, upstream tag, and upstream commit, and the artifact embeds provenance records.
- Isolated inherited release and repository-management automation while retaining build checks, and established independent Beacon synchronization and release processes.
- Established this changelog as the product change record instead of maintaining a separate downstream delta ledger.

### Initial import

- Imported the complete source tree from historical downstream commit `73a8f7edd0415f0e8651d3d1f3f295e6e6d4d1ea`. The adopted official release ancestor was OTel Java Instrumentation `v2.30.0`.
- Inherited legacy JDBC configuration compatibility, experimental JFR Profiling and DataKit export, Spring AI, Spring AI Alibaba Agent, and HSF instrumentation. These implementations existed in the previous branch; they were not newly developed after migration and had not completed Beacon acceptance at import time.

### Known limitations

- Profiling remains an inherited experimental implementation, and migration to an Extension is not complete. See the [development guide](README.md#profiling-extension-boundary) for the intended direction.
- The startup log prefix and default `telemetry.distro.name` still come from the inherited implementation. The Beacon agent file name and Manifest identity do not imply that every runtime identifier has been rebranded.

# Beacon Security for Java

Beacon Security is an opt-in capability of the complete Beacon Java agent. Its implementation is
an internal extension in this repository and is embedded into `beacon-javaagent-<version>.jar` at
build time. Applications use one Java agent JAR; they do not download, configure, or version a
second extension JAR.

This module is not a separate `beacon-security-context` product or repository. Java-specific
instrumentation, build, tests, and releases remain owned by `beacon-java`. Cross-language product
documentation belongs in the Beacon product repository, while each future language implementation
belongs in that language's repository.

The language-neutral event, identity, configuration, fingerprint, and runtime SBOM contract lives
in [beacon-security-spec](https://github.com/beacon-observability/beacon-security-spec). This
repository pins an immutable specification revision in
[`beacon/security-spec.properties`](../../beacon/security-spec.properties); the complete Agent JAR
embeds that record under `META-INF/beacon/` and exposes the versions in its Manifest.

The Java output uses schema version 2 for runtime-only identity as described below. The pinned
specification revision includes the matching v2 event contract and retains the unchanged
fingerprint version 1 vectors. V1 schemas remain available for historical consumers.

## Current status

Beacon Java 1.1.0 publishes the embedded extension, runtime data-flow observation, security finding
events, local diagnostic snapshots, and runtime CycloneDX SBOM in the complete Agent. Findings are
runtime observations or candidate risks; they are not claims that a vulnerability has been
confirmed. See the
[Beacon Java 1.1.0 release](https://github.com/beacon-observability/beacon-java/releases/tag/v1.1.0)
for the immutable Agent, checksum, SPDX SBOM, provenance, licenses, and attestations.

Security is disabled by default. Enabling it also enables the runtime SBOM unless explicitly
disabled. Production delivery uses the Java agent's OpenTelemetry Logs pipeline. Local JSON files
are diagnostic output and remain disabled by default.

## Download the released Agent

Download and verify the complete Agent before deploying it:

```bash
version=1.1.0
release="https://github.com/beacon-observability/beacon-java/releases/download/v$version"
curl --fail --location --remote-name "$release/beacon-javaagent-$version.jar"
curl --fail --location --remote-name "$release/beacon-javaagent-$version.jar.sha256"
sha256sum --check "beacon-javaagent-$version.jar.sha256"
```

The checksum file covers the Agent JAR. The same release also publishes the SPDX SBOM, provenance,
license, and third-party notices. There is no separate Security JAR to install.

## Build and verify

Use JDK 25 to build the complete agent:

```bash
export JAVA_HOME=/path/to/jdk-25
export PATH="$JAVA_HOME/bin:$PATH"

./gradlew :extensions:security:test :javaagent:assemble
```

The application-facing artifact is:

```text
javaagent/build/libs/beacon-javaagent-1.1.0.jar
```

The internal `extensions/beacon-security-extension.jar` entry in that artifact is a packaging
detail, not a separately supported distribution.

## Run a Java application

Environment variables are the recommended deployment interface:

```bash
BEACON_SECURITY_ENABLED=true \
OTEL_SERVICE_NAME=orders \
OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf \
OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4318 \
OTEL_LOGS_EXPORTER=otlp \
java -javaagent:/opt/beacon/beacon-javaagent-1.1.0.jar -jar orders.jar
```

The equivalent JVM-property form is useful for local debugging:

```bash
java \
  -javaagent:/opt/beacon/beacon-javaagent-1.1.0.jar \
  -Dbeacon.security.enabled=true \
  -Dotel.service.name=orders \
  -Dotel.exporter.otlp.protocol=http/protobuf \
  -Dotel.exporter.otlp.endpoint=http://127.0.0.1:4318 \
  -Dotel.logs.exporter=otlp \
  -jar orders.jar
```

The normal OpenTelemetry resource attributes identify the application. In particular,
`service.namespace` and `service.name` form the stable application identity; Beacon Security does
not introduce a second application-name setting.

### Runtime identity and migration

Schema version 2 removes `application_id` from Security events, component references, local
snapshots, and SBOM metadata. Use the existing `instance_id` UUID to identify the runtime process
and `service.namespace` / `service.name` to group its application. Consumers that map `instance_id`
to `runtime_id` should use that UUID as the runtime object key and display name, without an
application-ID prefix. Previously stored objects are not renamed by an Agent upgrade.

Production output is limited to `beacon.security.finding` (`source=beacon_security`) and
`beacon.security.sbom.inventory` (`source=beacon_security_sbom`). Inventory is collected and sent
every 300 seconds by default, even when unchanged. It contains dependencies and minimal identity,
time, and schema fields, plus `started_at` (JVM process start time in ISO 8601 UTC) and
`uptime_ms` (JVM uptime in milliseconds at collection start). Both come from RuntimeMXBean;
they are not framework readiness time or a live counter on historical logs. There are no collection
status/error fields. Failed collections emit no event; the next successful collection replaces the
previous inventory. Independent health, summary, diagnostic, dropped-record, and truncated-record
events are removed. SBOM IDs, revisions, release IDs, and history are removed.

Only large inventories include `part_index` and `part_count`. Collect all parts for the same
`instance_id` and `observed_at` before replacing the previous dependency list; all parts share
`started_at` and `uptime_ms`. An incomplete multipart update must not clear or partly replace the
previous list. A complete, valid empty list can clear it. Body `source` values are also attached as
OTel record attributes; collector-specific source mapping may differ from the body.

Findings carry `occurrence_id` instead of the duplicate `evidence_id`; component metadata is
provided directly as name/version/identity hash, and counts are aggregated by the backend.
Fingerprint version 1 remains unchanged. `collection_complete` records actual collection quality;
normal evidence sampling does not itself mark a record truncated. Full representative evidence
is retained in process only when local debug output is explicitly enabled.

Local `control.json` exceptions now require only `scope.finding_id`, whose stable fingerprint
already includes service identity. Exceptions are not tied to a process UUID. Update consumers
for schema version 2 before upgrading; a v1 event schema cannot validate v2 output. The local
[schema v2](schema-v2.json) is identical to the canonical schema in the pinned specification.

### Primary settings

| JVM property | Environment variable | Default | Purpose |
| --- | --- | --- | --- |
| `beacon.security.enabled` | `BEACON_SECURITY_ENABLED` | `false` | Enable runtime observation and Security lifecycle. |
| `beacon.security.sbom.enabled` | `BEACON_SECURITY_SBOM_ENABLED` | `true` | Collect runtime SBOM while Security is enabled. |
| `beacon.security.sbom.refresh.seconds` | `BEACON_SECURITY_SBOM_REFRESH_SECONDS` | `300` | Delay between completed dependency collections; each collection is exported. |
| `beacon.security.local-output.enabled` | `BEACON_SECURITY_LOCAL_OUTPUT_ENABLED` | `false` | Write process-local diagnostic snapshots. |
| `beacon.security.output` | `BEACON_SECURITY_OUTPUT` | `./beacon-security-output/<instance-id>` | Diagnostic snapshot directory. |
| `beacon.security.evidence.file` | `BEACON_SECURITY_EVIDENCE_FILE` | unset | Optional JSONL evidence file for diagnostics. |

Production SBOM collection resolves only the artifact locations observed from loaded classes.
For nested locations it follows the exact ZIP entry chain instead of scanning every library in the
enclosing application. Unloaded classpath entries and nested libraries are not parsed. ZIP directory
entries select Maven/manifest metadata without inflating unrelated class files or resources.
Maven coordinates are preferred, with `name=groupId:artifactId` and a separate `version`. For a
shaded JAR, a unique Maven coordinate matching the actual `artifactId-version.jar` filename
identifies its primary component. Explicit `group#artifact;version` Manifest titles also provide
coordinates when the artifact filename and Manifest version agree. Vendor IDs and OSGi bundle
names are not treated as Maven groups. Without these coordinates, the actual JAR filename identifies
the artifact; an exact known version suffix is removed. Generic product titles such as
`Apache Tomcat` do not replace distinct artifact names. Unknown groups are omitted from `name`
and unknown versions remain empty, rather than inventing Maven coordinates.
Loaded class directories, including JSP compiler output, remain diagnostic application components
and are excluded from dependency inventory and finding component resolution.

Every exported dependency and finding component has the same `name`, `version`, `hash` shape.
`hash` is the lowercase 32-character MD5 of the UTF-8 compact JSON array `[name,version]`, with
the strings preserved exactly and no whitespace between array elements. For example,
`["org.example:library-a","1.0.0"]` hashes to `b783176a5feb4aafd51a712235824a9c`.
It is a metadata deduplication key and does not attest to file contents. Equal names and versions
deduplicate across paths and repackaged JARs. Consumers that previously used artifact SHA-256
values from `hash` must migrate their deduplication keys to this name/version identity.
The event field layout and schema version 2 remain unchanged; this Java hash policy supersedes
the earlier artifact-digest meaning of the optional schema field.

JDK installation libraries under `java.home/lib`, `java.home/jre/lib`, and the enclosing JDK's
`lib` directory when `java.home` ends in `jre` are excluded, including Java 8 extension libraries.
Resolved filesystem paths distinguish these from application-supplied libraries with the same name.
Production collection does not hash archive contents. The origin distinguishes physical copies
internally. Local diagnostic output still scans the full classpath and supported
nested libraries, with content hashes, licenses, and embedded SBOM metadata.

Successfully parsed metadata is reused while the outer file's size, modification time, and file key
are unchanged. Every collection still rebuilds the currently loaded list and exports a complete
snapshot, including when unchanged or empty after a previous nonempty snapshot. Before the first
dependency is observed, collection retries every second without publishing an empty startup list;
the normal refresh interval starts after the first nonempty inventory. New origins and changed files are parsed; failures
are retried on the next collection. `beacon.security.sbom.cache.seconds` is no longer used to expire
successful parses. File attributes are a cache invalidation check, not a content-integrity check.

Selected nested JARs are copied to bounded temporary files under the JVM temporary directory
(`java.io.tmpdir`); the files are deleted after scanning, including when scanning fails. This directory
must be writable when scanning nested libraries. Diagnostic scans hash during copying; production
scans read only the selected metadata from staged archives. Standard local CycloneDX `hashes`
remain actual SHA-256 artifact digests and are separate from exported MD5 identity keys.

| JVM property | Environment variable | Default | Purpose |
| --- | --- | --- | --- |
| `beacon.security.sbom.max.archive.bytes` | `BEACON_SECURITY_SBOM_MAX_ARCHIVE_BYTES` | `67108864` (64 MiB) | Maximum size of each nested JAR copied for scanning. Does not limit unrelated resource entries. |
| `beacon.security.sbom.max.scan.bytes` | `BEACON_SECURITY_SBOM_MAX_SCAN_BYTES` | `536870912` (512 MiB) | Read budget per resolved origin (per outer artifact in diagnostic mode): copied nested JARs, selected metadata, and any SHA-256 input. Skipped resource contents are not read or counted. |
| `beacon.security.sbom.max.entries` | `BEACON_SECURITY_SBOM_MAX_ENTRIES` | `100000` | Maximum directory entries visited per resolved origin (per outer artifact in diagnostic mode), including the selected nested entry chain. |

Metadata reads remain bounded to 256 KiB per Maven/manifest entry and 1 MiB per embedded CycloneDX
JSON document. Nested archives are scanned to at most four levels. Byte-limit warnings include the
artifact/entry location, configured limit, and observed size. `archive_byte_limit` identifies an
oversized nested JAR, `metadata_byte_limit` an oversized metadata entry, and `scan_byte_limit` the
total read budget. A collection that reaches a limit emits no inventory update and retains the
previous published inventory.

OpenTelemetry settings such as `OTEL_EXPORTER_OTLP_ENDPOINT`,
`OTEL_EXPORTER_OTLP_HEADERS`, and `OTEL_RESOURCE_ATTRIBUTES` configure transport and resource
identity. Beacon does not duplicate those settings.

Security settings are startup configuration. Restart the process to change enablement, budgets,
rule settings, or instrumentation selection; mutating JVM properties during requests is not a
runtime control interface. Local `control.json` policy revisions still support pause/resume and
triage updates without a restart.

Unreachable request states are reclaimed through a Java 8 compatible reference queue. Reclamation
releases process byte reservations and active-request leases, reports `requests_abandoned`, and
marks coverage incomplete. Explicit close and normal completion are idempotent. Live long-running
requests remain counted; no arbitrary timeout closes their shared state or their nested spans.

### Export budgets and priorities

Security exports use two bounded queues: suspected attack evidence and ordinary occurrences.
SBOM inventory uses its own bounded queue; no diagnostic queue or pending-loss replay is retained.
The default security limit remains 100 events
and 524288 bytes per second. Ordinary events can use at most 80 events and three quarters of the
byte limit; the remaining budget is reserved for higher priorities. If the configured event limit
is one, an event reservation cannot be made. All lanes remain best effort when their own capacity
or the total budget is exhausted. Per-request occurrence identifiers and trace correlation are
preserved; ordinary events are not merged across requests.

| JVM property | Environment variable | Default | Purpose |
| --- | --- | --- | --- |
| `beacon.security.export.queue.size` | `BEACON_SECURITY_EXPORT_QUEUE_SIZE` | `1024` | Ordinary occurrence queue capacity. |
| `beacon.security.export.priority.queue.size` | `BEACON_SECURITY_EXPORT_PRIORITY_QUEUE_SIZE` | `128` | Suspected attack evidence queue capacity. |

Local debug `status=incomplete` and `delivery_loss` fields retain cumulative coverage-loss
semantics. `current_delivery_status` separately reports loss observed during the last 60 seconds,
using `delivery.security_loss_recent`; `no_recent_loss_observed` is not a backend acknowledgement
or a guarantee that pending events have arrived. Historical loss remains visible after the window.

For a local inspection without an OTLP backend:

```bash
BEACON_SECURITY_ENABLED=true \
BEACON_SECURITY_LOCAL_OUTPUT_ENABLED=true \
BEACON_SECURITY_OUTPUT=/tmp/beacon-security \
BEACON_SECURITY_EVIDENCE_FILE=/tmp/beacon-security/evidence.jsonl \
OTEL_TRACES_EXPORTER=none \
OTEL_METRICS_EXPORTER=none \
OTEL_LOGS_EXPORTER=none \
java -javaagent:javaagent/build/libs/beacon-javaagent-1.1.0.jar -jar app.jar
```

This produces `findings.json`, `health.json`, `runs.json`, and `application.cdx.json`. These files
are per-process diagnostics, not a Kubernetes aggregation or durable delivery mechanism.

## Finding occurrences and attack evidence

Every request that triggers a finding now exports an occurrence, even inside the full-evidence
sampling interval. The fingerprint remains stable; `occurrence_id` uniquely identifies this
request's finding. Repeated detections of that fingerprint within one request are deduplicated, with
stronger evidence allowed to upgrade the record without incrementing its count.

Online findings are emitted only when a security rule detects input flowing into a modeled
sensitive call. All Security logs use OTel INFO severity. `attack_evidence.status` retains
`unknown`, `no_evidence`, and `suspected`, with a `reason` explaining the classification.
Unavailable analysis does not suppress an otherwise matching finding.

| Status | Meaning |
| --- | --- |
| `unknown` | Analysis is unavailable, unsupported, imprecise, or requires missing policy. |
| `no_evidence` | Supported analysis found no attack evidence. This does not establish safety. |
| `suspected` | Input influences potentially dangerous syntax in a supported context. This does not establish exploit success. |

Exported findings omit fixed assessment/validation/severity/confidence fields and the constant
`attack_evidence.outcome`. Service, runtime, and code metadata come from OTel Resource instead of
repeated body maps. Request metadata is limited to method, route, status code, and a non-empty
error type; empty sink fields are omitted. A current span ID equal to the server span ID is omitted.
Raw SQL, shell scripts, and request values are not added to exported evidence. Fixed SQL parameter
binding remains separate from concatenation into a template before preparation.

### Analysis support and limits

SQL analysis is opt-in using `BEACON_SECURITY_ANALYSIS_SQL_DIALECT=ansi` (JVM property
`beacon.security.analysis.sql.dialect`). The default `unknown` preserves uncertainty when the
application's dialect is not specified. Enable `ansi` only for compatible SQL: it analyzes a
lexical subset with single-quoted strings, doubled quote escapes, quoted identifiers, decimal
numbers, operators, parentheses, and comments. It identifies tainted structural operators or
comment delimiters, not keyword matches. This is not a complete SQL parser. Backslash escapes,
dollar quoting, backticks, bracket quoting, incomplete quotes, and unsupported syntax remain
unknown. Tainted identifiers alone remain unknown. Mixed-dialect applications should leave the
setting unknown until they can provide an appropriate per-connection dialect model.

Shell analysis supports simple POSIX scripts passed as an individual argument to `sh`, `bash`,
`dash`, `ksh`, or `zsh`: quotes, backslash escapes, and control separators. Expansions, substitutions,
redirections, compound constructs, Windows shells, and scripts reconstructed from
`Runtime.exec(String)` remain unknown. Ordinary argv input is not classified as shell injection;
this does not exclude application-specific argument risks.

Each analysis examines at most 8,192 UTF-16 code units and 64 exact taint ranges. Larger inputs,
imprecise ranges, unsupported syntax, or missing inputs return unknown with a reason. It performs
no network requests, command execution, replay, JDBC metadata calls, or filesystem resolution.
SSRF destination control, executable selection, and file paths remain unknown for attack
assessment without an applicable boundary policy. Fixed-host path/query input remains an
observation; `normalize()` alone never establishes path safety. This release does not implement
network allowlists or filesystem root policies. `trim`, `subSequence`, and character replacement
preserve taint offsets where modeled; replacement is not treated as universal sanitization.

### Sampling, aggregation, and migration

| JVM property | Environment variable | Default | Meaning |
| --- | --- | --- | --- |
| `beacon.security.findings.sample.seconds` | `BEACON_SECURITY_FINDINGS_SAMPLE_SECONDS` | `300` | Full-evidence interval per finding; occurrence records are still exported. Positive integers only; zero falls back to the default. |
| `beacon.security.analysis.sql.dialect` | `BEACON_SECURITY_ANALYSIS_SQL_DIALECT` | `unknown` | `ansi` enables the documented SQL lexical subset; other values remain unknown. |

A sampled-out record has `evidence_sampled=false` and a sampling reason; its
`sources`, `propagation`, `ranges`, and `stack` arrays are omitted. `truncated=true` marks actual
loss from a collection or encoding limit (absent means false), and `collection_complete`
separately describes collection quality. Those omitted arrays do not mean no taint was
observed. Request metadata, finding identity, and trace correlation remain.
First samples and stronger evidence bypass the ordinary interval. Later ordinary samples cannot
replace a stronger retained representative; `last_trace_id` may differ from its trace ID.
Online summaries and cumulative occurrence totals are removed. The backend counts unique
occurrences and can classify their `attack_evidence.status`; these are not confirmed attack counts.

Consumers must honor sampling and collection-quality fields and must not assume every finding
contains full evidence. Fingerprint v1 remains unchanged. When the bounded sampling table is full,
new findings still produce occurrence records with `evidence_sampled=false` and
`evidence_sample_reason=finding_capacity`. There is no guarantee that a correlated trace was
exported or that every occurrence reached the backend. No diagnostic or replay event is generated
to compensate for loss.

## Kubernetes

The [container distribution](../../beacon/docker/javaagent/README.md) packages the complete,
already published Agent JAR, including the opt-in Security extension. Its separate workflow
publishes version-only GHCR tags after native image acceptance and protected promotion.

Replace the application image placeholder and Collector endpoint in the
[initContainer example](examples/kubernetes/init-container.yaml), then apply it:

```bash
kubectl apply -f extensions/security/examples/kubernetes/init-container.yaml
kubectl rollout status deployment/orders
```

The initContainer copies one Agent JAR into an `emptyDir`; the application uses it through
`JAVA_TOOL_OPTIONS`. Security events, traces, and metrics then share the same Agent and OTLP
connection. Keep local output disabled in normal Kubernetes workloads.

An OpenTelemetry Operator `Instrumentation` resource can later reduce each workload change to an
annotation, but adding that dependency and validating Operator injection compatibility require a
separate acceptance decision. Operator injection is not a current release capability.

## End-to-end smoke test

The repository contains a minimal Boot 2 Security validation fixture. Build it and pass it to the
smoke script together with the complete Agent:

```bash
export JAVA_HOME=/path/to/jdk-21
export PATH="$JAVA_HOME/bin:$PATH"

./gradlew :javaagent:assemble
./gradlew -p beacon/testing/security-smoke-fixture shadowJar
version=$(sed -n 's/^version=//p' beacon/version.properties)
node beacon/scripts/security-smoke.cjs \
  "javaagent/build/libs/beacon-javaagent-$version.jar" \
  beacon/testing/security-smoke-fixture/build/libs/beacon-security-smoke-fixture.jar
```

It verifies separate trace correlation for repeated dynamic-SQL requests, immediate export of
stronger evidence inside the sampling window, and independent classification of later ordinary
requests. It also verifies that a dynamically concatenated prepared template retains its risk,
fixed parameterized and constant SQL do not produce findings, runtime SBOM is present, the product
version is resolved, and delivery reports no local loss.

Local acceptance on 2026-10-01 ran the earlier single-request scenario with JDK 8u461, 11.0.18,
17.0.6, and 21.0.3. All four passed. That historical result predates the occurrence and attack-evidence
assertions above. See the implementation PR for their validation results and the release acceptance
matrix for supported-runtime coverage.

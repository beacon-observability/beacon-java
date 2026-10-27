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

### Primary settings

| JVM property | Environment variable | Default | Purpose |
| --- | --- | --- | --- |
| `beacon.security.enabled` | `BEACON_SECURITY_ENABLED` | `false` | Enable runtime observation and Security lifecycle. |
| `beacon.security.sbom.enabled` | `BEACON_SECURITY_SBOM_ENABLED` | `true` | Collect runtime SBOM while Security is enabled. |
| `beacon.security.local-output.enabled` | `BEACON_SECURITY_LOCAL_OUTPUT_ENABLED` | `false` | Write process-local diagnostic snapshots. |
| `beacon.security.output` | `BEACON_SECURITY_OUTPUT` | `./beacon-security-output/<instance-id>` | Diagnostic snapshot directory. |
| `beacon.security.evidence.file` | `BEACON_SECURITY_EVIDENCE_FILE` | unset | Optional JSONL evidence file for diagnostics. |

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

Security exports use three bounded queues, in order: suspected attack evidence, collection/export
diagnostics, then ordinary occurrences and summaries. The default security limit remains 100 events
and 524288 bytes per second. Ordinary events can use at most 80 events and three quarters of the
byte limit; the remaining budget is reserved for higher priorities. If the configured event limit
is one, an event reservation cannot be made. All lanes remain best effort when their own capacity
or the total budget is exhausted. Per-request occurrence identifiers and trace correlation are
preserved; ordinary events are not merged across requests.

| JVM property | Environment variable | Default | Purpose |
| --- | --- | --- | --- |
| `beacon.security.export.queue.size` | `BEACON_SECURITY_EXPORT_QUEUE_SIZE` | `1024` | Ordinary occurrence queue capacity. |
| `beacon.security.export.priority.queue.size` | `BEACON_SECURITY_EXPORT_PRIORITY_QUEUE_SIZE` | `128` | Suspected attack evidence queue capacity. |
| `beacon.security.export.diagnostic.queue.size` | `BEACON_SECURITY_EXPORT_DIAGNOSTIC_QUEUE_SIZE` | `64` | Diagnostic queue capacity. |

The existing `status=incomplete` and `delivery_loss` fields retain cumulative coverage-loss
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
sampling interval. The fingerprint remains stable; `occurrence_id` equals the request's unique
`evidence_id`. Repeated detections of that fingerprint within one request are deduplicated, with
stronger evidence allowed to upgrade the record without incrementing its count.

The optional `attack_evidence` object separates request evidence from code risk:

| Status | Meaning |
| --- | --- |
| `unknown` | Analysis is unavailable, unsupported, imprecise, or requires missing policy. |
| `no_evidence` | Supported analysis found no attack evidence. This does not establish safety. |
| `suspected` | Input influences potentially dangerous syntax in a supported context. This does not prove intent or successful exploitation. |

`assessment` remains `observation` or `candidate_risk`, and `validation` remains `unvalidated`.
`attack_evidence.outcome` is always `not_assessed`. Raw SQL, shell scripts, and request values are
not added to exported evidence. Prepared statements retain only the bounded assessment of their
SQL template in request state, not the raw template. Fixed SQL parameter binding remains separate
from concatenation into a template before preparation.

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
| `beacon.security.findings.flush.seconds` | `BEACON_SECURITY_FINDINGS_FLUSH_SECONDS` | `30` | Aggregate summary interval. |
| `beacon.security.analysis.sql.dialect` | `BEACON_SECURITY_ANALYSIS_SQL_DIALECT` | `unknown` | `ansi` enables the documented SQL lexical subset; other values remain unknown. |

A sampled-out record has `evidence_sampled=false`, a sampling reason, `truncated=true`, and empty
`sources`, `propagation`, `ranges`, and `stack` arrays. Those empty arrays do not mean no taint was
observed. Request metadata, finding identity, trace correlation, and attack assessment remain.
First samples and stronger evidence bypass the ordinary interval. Later ordinary samples cannot
replace a stronger retained representative; `last_trace_id` may differ from its trace ID.
Summaries expose separate `unknown`, `no_evidence`, and `suspected` occurrence counters in
`attack_evidence_counts`. These are not confirmed attack counts.

Consumers must honor sampling/truncation fields and must not assume every finding contains full
evidence. Existing required fields and fingerprint v1 remain unchanged; new fields are additive.
Repeated findings produce more log records than before. Queue and byte limits still apply and
loss counters remain authoritative. A full aggregation table no longer suppresses the occurrence:
`aggregation_status=capacity_exceeded` omits `occurrences_total`. There is no guarantee that a
correlated trace was exported, nor a guarantee of lossless event delivery.

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

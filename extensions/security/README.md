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

The embedded extension, runtime data-flow observation, security finding events, local diagnostic
snapshots, and runtime CycloneDX SBOM are implemented and locally validated. They have not yet been
published as part of an accepted Beacon Java release. Findings are runtime observations or
candidate risks; they are not claims that a vulnerability has been confirmed.

Security is disabled by default. Enabling it also enables the runtime SBOM unless explicitly
disabled. Production delivery uses the Java agent's OpenTelemetry Logs pipeline. Local JSON files
are diagnostic output and remain disabled by default.

## Build and verify

Use JDK 21 to build the complete agent:

```bash
export JAVA_HOME=/path/to/jdk-21
export PATH="$JAVA_HOME/bin:$PATH"

./gradlew :extensions:security:test :javaagent:assemble
```

The application-facing artifact is:

```text
javaagent/build/libs/beacon-javaagent-1.0.0.jar
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
java -javaagent:/opt/beacon/beacon-javaagent-1.0.0.jar -jar orders.jar
```

The equivalent JVM-property form is useful for local debugging:

```bash
java \
  -javaagent:/opt/beacon/beacon-javaagent-1.0.0.jar \
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

For a local inspection without an OTLP backend:

```bash
BEACON_SECURITY_ENABLED=true \
BEACON_SECURITY_LOCAL_OUTPUT_ENABLED=true \
BEACON_SECURITY_OUTPUT=/tmp/beacon-security \
BEACON_SECURITY_EVIDENCE_FILE=/tmp/beacon-security/evidence.jsonl \
OTEL_TRACES_EXPORTER=none \
OTEL_METRICS_EXPORTER=none \
OTEL_LOGS_EXPORTER=none \
java -javaagent:javaagent/build/libs/beacon-javaagent-1.0.0.jar -jar app.jar
```

This produces `findings.json`, `health.json`, `runs.json`, and `application.cdx.json`. These files
are per-process diagnostics, not a Kubernetes aggregation or durable delivery mechanism.

## Kubernetes

The checked-in [Dockerfile](../../beacon/docker/javaagent/Dockerfile) packages the complete Agent as
an init image. No registry image is published by this change. Build a local or private-registry
image from the repository root:

```bash
docker build \
  -f beacon/docker/javaagent/Dockerfile \
  --build-arg AGENT_JAR=beacon-javaagent-1.0.0.jar \
  -t registry.example.com/observability/beacon-javaagent:1.0.0 \
  javaagent/build/libs
docker push registry.example.com/observability/beacon-javaagent:1.0.0
```

Replace the two image placeholders and Collector endpoint in the
[initContainer example](examples/kubernetes/init-container.yaml), then apply it:

```bash
kubectl apply -f extensions/security/examples/kubernetes/init-container.yaml
kubectl rollout status deployment/orders
```

The initContainer copies one Agent JAR into an `emptyDir`; the application uses it through
`JAVA_TOOL_OPTIONS`. Security events, traces, and metrics then share the same Agent and OTLP
connection. Keep local output disabled in normal Kubernetes workloads.

An OpenTelemetry Operator `Instrumentation` resource can later reduce each workload change to an
annotation, but adding that dependency and publishing a compatible injection image require a
separate acceptance decision. They are not current release capabilities.

## End-to-end smoke test

The repository smoke script accepts the runnable Boot 2 Security validation fixture JAR:

```bash
export JAVA_HOME=/path/to/jdk-21
export PATH="$JAVA_HOME/bin:$PATH"

node beacon/scripts/security-smoke.cjs \
  javaagent/build/libs/beacon-javaagent-1.0.0.jar \
  /path/to/security-validation-boot2.jar
```

It verifies that dynamic SQL produces one `sql_injection` finding, parameterized and constant SQL
do not produce findings, runtime SBOM is present, product version is resolved, and delivery reports
no local loss.

Local acceptance on 2026-10-01 ran that complete scenario with JDK 8u461, 11.0.18, 17.0.6, and
21.0.3. All four passed. This is local compatibility evidence, not a substitute for the release
acceptance matrix or a published support commitment.

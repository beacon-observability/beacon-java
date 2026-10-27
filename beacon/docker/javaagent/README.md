# Beacon Java container image

The image distributes the complete, already published Beacon Java Agent. It contains no JVM or
application. Use it in a multi-stage Docker build or as a Kubernetes init container. Security remains
embedded in the same JAR and disabled by default.

The image name is `ghcr.io/beacon-observability/beacon-java`. Tags contain only the Beacon version,
for example `1.3.2`; no `v`, runtime, architecture, or packaging suffix is added. The version tag is
published once and must not be overwritten. Linux amd64 and arm64 share one manifest list. Runtime
and feature support are still defined by the corresponding Agent release; image availability does
not expand that scope. Production deployments should pin the manifest digest.

## Contents

| Path | Content |
| --- | --- |
| `/javaagent.jar` | Exact complete JAR from the matching GitHub Release |
| `/licenses/` | Product license and third-party notices from that release |
| `/metadata/provenance.json` | Original release source and Agent SHA-256 |
| `/metadata/beacon-javaagent-<version>.jar.sha256` | Original JAR checksum |
| `/metadata/agent.spdx.json` | Original **Agent** SBOM, not a full container SBOM |

The BusyBox base is pinned by multi-platform digest. The default user is `65532:65532`; all product
files are readable without root. The container needs no network access to copy the Agent.

## Application image

```dockerfile
FROM ghcr.io/beacon-observability/beacon-java:1.3.2 AS beacon
FROM eclipse-temurin:21-jre
COPY --from=beacon /javaagent.jar /opt/beacon/javaagent.jar
COPY application.jar /app/application.jar
ENV JAVA_TOOL_OPTIONS="-javaagent:/opt/beacon/javaagent.jar"
ENTRYPOINT ["java", "-jar", "/app/application.jar"]
```

Select a JVM supported by your Agent and application, and append the Agent option to any existing
`JAVA_TOOL_OPTIONS`. Supply service identity, OTLP endpoints, and optional feature settings at
deployment time. Do not bake credentials into the image.

## Kubernetes

The [initContainer example](../../../extensions/security/examples/kubernetes/init-container.yaml)
copies `/javaagent.jar` into an `emptyDir` with `fsGroup: 65532`. The application mounts it read-only
and loads it through `JAVA_TOOL_OPTIONS`. Replace the application image and Collector endpoint;
Security is explicitly enabled by that Security example.

This is a manually configured init-container interface. Compatibility with the OpenTelemetry
Operator's injection images and admission workflow is not claimed.

## Build and release

Run the [Beacon Java image workflow](../../../.github/workflows/beacon-image.yml) from `main` with
an existing stable release version. This is a separate distribution step; it does not rebuild the
JAR, create a new product release, or modify an existing Git tag.

Pull requests touching the image implementation also build and test both architectures against
the pinned public `1.3.2` release. Pull-request runs never publish packages.

1. Each native amd64/arm64 runner downloads the published JAR, checksum, SBOM, provenance, and
   licenses. The preparation script verifies their version, source commit, Manifest, and digest.
2. Build each image once. Verify its labels, non-root read-only copy operation, byte-identical JAR,
   HTTP context propagation, and correlated OTLP trace export on that native architecture.
3. Upload those tested images as workflow artifacts. The publish job uses the existing
   `beacon-release` environment approval and promotes the archives without rebuilding.
4. Reject an existing version tag. Upload the two platform manifests by digest and publish only the
   version tag. Record the final manifest digest in the workflow summary.
5. On first publication, a package administrator must set the GHCR package visibility to **public**.
   Verify anonymous pulling and run the Kubernetes smoke test against the published image.

The publish job uses `GITHUB_TOKEN` with `packages: write`; no personal package token is required.
Keep the environment reviewers and repository protections enabled. If an interrupted publication
has uploaded only untagged platform manifests, rerun the workflow. If the version tag already exists,
verify it and roll back by digest rather than overwriting it.

For a local build, with Node.js, GitHub CLI, Docker, `unzip`, and a JDK available:

```bash
node beacon/docker/javaagent/prepare.cjs 1.3.2 /tmp/beacon-java-release
source=$(node -p 'require("/tmp/beacon-java-release/provenance.json").source_commit')
docker buildx build --load \
  -f beacon/docker/javaagent/Dockerfile \
  --build-arg BEACON_VERSION=1.3.2 \
  --build-arg "BEACON_SOURCE_REVISION=$source" \
  -t ghcr.io/beacon-observability/beacon-java:1.3.2 \
  /tmp/beacon-java-release
bash beacon/docker/javaagent/verify-image.sh \
  ghcr.io/beacon-observability/beacon-java:1.3.2 /tmp/beacon-java-release
```

The staging directory must be empty. A local build is for diagnosis and Kubernetes acceptance;
formal publication uses the tested workflow archives.

## Kubernetes smoke test

The smoke script requires an explicit kubeconfig context. It creates a uniquely named namespace,
an in-cluster OTLP test receiver, and a Java Job; it deletes that namespace on success or failure.
It does not change the current context or deploy into existing application namespaces.

```bash
node beacon/docker/javaagent/kubernetes-smoke.cjs \
  YOUR_TEST_CONTEXT \
  ghcr.io/beacon-observability/beacon-java:1.3.2 \
  1.3.2 \
  AGENT_SHA256_FROM_THE_RELEASE
```

The test verifies the init-container copy checksum, Agent startup version, non-root containers,
read-only application filesystem and Agent mount, trace-context propagation, and actual correlated
OTLP/HTTP protobuf delivery. It keeps Security disabled and does not substitute for Security or
Profiling feature acceptance in the Agent release.

Set `BEACON_K8S_JAVA_IMAGE` or `BEACON_K8S_PYTHON_IMAGE` to use reachable equivalents of the default
`eclipse-temurin:21-jdk` and `python:3.12-slim` fixture images. For kind, load local images before the
test. The resulting acceptance scope is the cluster architecture actually tested.

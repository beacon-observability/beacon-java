FROM busybox:1.37.0@sha256:bdf57e528e45e4433820e045b29b4597825a1c9e38353532d90a01445013f82e

ARG BEACON_VERSION
ARG BEACON_SOURCE_REVISION

LABEL org.opencontainers.image.title="Beacon Java" \
      org.opencontainers.image.description="Complete Beacon Java agent for multi-stage builds and Kubernetes init containers" \
      org.opencontainers.image.source="https://github.com/beacon-observability/beacon-java" \
      org.opencontainers.image.url="https://github.com/beacon-observability/beacon-java/releases" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${BEACON_VERSION}" \
      org.opencontainers.image.revision="${BEACON_SOURCE_REVISION}"

COPY --chmod=0444 beacon-javaagent-${BEACON_VERSION}.jar /javaagent.jar
COPY --chmod=0444 LICENSE THIRD_PARTY_LICENSES.md /licenses/
COPY --chmod=0444 provenance.json beacon-javaagent-${BEACON_VERSION}.jar.sha256 /metadata/
COPY --chmod=0444 beacon-javaagent-${BEACON_VERSION}.spdx.json /metadata/agent.spdx.json

RUN chmod 0555 /licenses /metadata

USER 65532:65532

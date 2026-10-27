#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

image=${1:?Usage: verify-image.sh <image> <release-directory>}
stage=$(realpath "${2:?Missing release directory}")
root=$(cd "$(dirname "$0")/../../.." && pwd)
version=$(node -p 'JSON.parse(require("fs").readFileSync(process.argv[1])).version' "$stage/provenance.json")
digest=$(node -p 'JSON.parse(require("fs").readFileSync(process.argv[1])).agent_sha256' "$stage/provenance.json")
source=$(node -p 'JSON.parse(require("fs").readFileSync(process.argv[1])).source_commit' "$stage/provenance.json")
[[ $(docker image inspect "$image" --format '{{.Config.User}}') == '65532:65532' ]]
[[ $(docker image inspect "$image" --format '{{index .Config.Labels "org.opencontainers.image.version"}}') == "$version" ]]
[[ $(docker image inspect "$image" --format '{{index .Config.Labels "org.opencontainers.image.revision"}}') == "$source" ]]

# Exercise the actual init-container copy as the image's unprivileged user.
docker run --rm --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges --tmpfs /target:rw,size=40m,mode=0777 \
  --env "EXPECTED_SHA256=$digest" --entrypoint sh "$image" -ec '
    test "$(id -u)" = 65532
    cp /javaagent.jar /target/javaagent.jar
    printf "%s  /target/javaagent.jar\n" "$EXPECTED_SHA256" | sha256sum -c -
    test -r /licenses/LICENSE
    test -r /licenses/THIRD_PARTY_LICENSES.md
    test -r /metadata/agent.spdx.json
  '

directory=$(mktemp -d)
container=''
cleanup() {
  if [[ -n "$container" ]]; then docker rm "$container" >/dev/null; fi
  rm -rf "$directory"
}
trap cleanup EXIT
container=$(docker create "$image")
agent="$directory/beacon-javaagent-$version.jar"
docker cp "$container:/javaagent.jar" "$agent"
cmp "$stage/beacon-javaagent-$version.jar" "$agent"
node "$root/beacon/scripts/release-metadata.cjs" verify-artifact "$agent" "$version" "$digest"
node "$root/beacon/scripts/agent-smoke.cjs" "$agent"
echo "PASS: image identity, non-root copy and exact released Agent OTLP export ($version)."

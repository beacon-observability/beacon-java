# Beacon Java Release Process

Beacon uses an independent product version and artifact identity. The [packaging configuration](agent.gradle.kts) is loaded by `:javaagent`. Repository conditions prevent inherited official and legacy downstream publication jobs from serving as Beacon release entry points; see the [CI guide](CI.md). Beacon has separate [preparation](../.github/workflows/beacon-prepare-release.yml) and [publication](../.github/workflows/beacon-release.yml) workflows; neither calls inherited Maven, Sonatype, plugin, or image publication.

## Versioning and scope

- Beacon Java uses independent semantic versions and `vX.Y.Z` tags. Official upstream tags are fetched into the separate `refs/upstream-tags/` namespace and are not published as Beacon release tags.
- [version.properties](version.properties) is the only source of the product version. Stable releases use `X.Y.Z`, public release candidates use `X.Y.Z-rc.N`, and development versions use `X.Y.Z-SNAPSHOT`. Do not publish a SNAPSHOT as a formal release or override the release version through an ad hoc command-line property.
- The product version and [upstream baseline](upstream.lock.json) are recorded separately. Do not globally replace the upstream build version or modify the instrumented application's `service.version`.
- The complete installation package is `beacon-javaagent-<Beacon-version>.jar`. Helper artifacts such as `base` and `dontuse` are not published as Beacon installation packages. Do not publish the Beacon product through inherited Maven or Sonatype publication tasks.
- Manifest attributes `Implementation-Title`, `Implementation-Version`, and `Implementation-Vendor` identify the Beacon product. `Beacon-Upstream-Tag` and `Beacon-Upstream-Commit` identify the official baseline. `Beacon-Instrumentation-Version` retains the currently inherited module build version. Embedded files under `META-INF/beacon/` preserve version and provenance records.
- Do not bulk-rename upstream module coordinates, Java packages, or instrumentation scopes. The complete JAR's `java -jar` version output and AgentVersion read the Manifest and therefore use the Beacon product version; the module build version is available separately through `Beacon-Instrumentation-Version`. The default `telemetry.distro.name` is `beacon-java-instrumentation` for both flat and declarative configuration, paired with the Beacon product version in `telemetry.distro.version`. Existing startup log prefixes still come from inherited runtime code. Do not describe the file-name change as a complete rebranding of all runtime identifiers.
- State the functionality and support scope actually validated for each release. The current Profiling implementation is inherited and experimental. Its conversion to an Extension is a separate effort and is not a prerequisite for the initial source publication.
- Publish source provenance, licenses, required third-party notices, artifact digests, SPDX SBOM,
  and known limitations with each release. GitHub Releases is the current artifact host, and the
  publication workflow creates GitHub build-provenance attestations through OIDC.

## Release sequence

1. Add user-visible changes under `Unreleased` and prepare the target product version in a pull request. Use one of these paths:
   - For a standalone release, run **Prepare Beacon release** from `main` with the target version. It updates `version.properties`, moves completed changelog entries, opens a release pull request, and requests one normal Beacon CI run. The explicit dispatch is needed because events created with `GITHUB_TOKEN` do not automatically trigger another PR workflow.
   - When an upstream synchronization PR also prepares a release, explicitly select the Beacon product version and run `node beacon/scripts/release-metadata.cjs prepare <version>` in that PR's worktree. Review the version and changelog changes together with the synchronization, validate the new-version artifact, and merge using a merge commit to preserve upstream ancestry. Do not run **Prepare Beacon release** again to create a duplicate PR.
   - Keep Beacon product notes separate from the full upstream changelog. The PR prepares source metadata; it does not create a release tag or publish artifacts.
2. Wait for the release PR's selected Beacon CI tier to succeed, then merge. A regular PR uses
   the normal 8-job matrix; shared build, agent core, and CI changes use the 16-job upgrade matrix.
   The 48-job `full` profile remains an explicit option for expanded acceptance, rather than a
   mandatory second validation after every merge. Add Windows, OpenJ9, performance, or other
   targeted testing according to the declared support scope.
3. Run **Beacon release** against the merged source, supplying the committed version. Leave
   `validation_run_id` empty to discover a successful PR or manual CI run with the **same complete
   Git tree**, or supply its ID explicitly. The validator checks the actual PR test-merge tree,
   not just the PR head SHA. It rejects different content, failed/missing selected jobs, substituted
   or duplicate test matrix entries, fork artifacts, and missing or expired candidate artifacts.
   A merge or squash that changes only commit identity can reuse validation. A merge that adds
   file changes must be validated again. Source, build configuration, workflows, tests, version,
   and documentation are all included in the tree comparison; there are no ignored-path exceptions.
4. CI's cache-isolated build produces the JAR and SPDX SBOM once, runs HTTP, Security, and JDBC
   acceptance against that JAR, and uploads the candidate plus a SHA-256 inventory and validation
   plan. Release downloads and verifies those exact bytes; it does not compile or repeat the module
   matrix. The `beacon-release` GitHub Environment gates the publish job. After approval, publication
   revalidates the payload, creates the immutable tag and build-provenance attestation, publishes
   without rebuilding, and downloads the public assets for digest and HTTP/Security smoke checks.
   Provenance records both the release commit and original build commit plus their identical Git
   tree. The unchanged SPDX document identifies the original build commit.
5. If the product version, Manifest, or any artifact content changes, rebuild and validate again. A public release candidate whose content differs from the stable release cannot simply be renamed as the same artifact.
6. Link user documentation and the support scope to the version. For the first release or when entry points or support status change, update the [Beacon product repository](https://github.com/beacon-observability/beacon). Cross-repository registration is not required for every patch release.

The publish job is bound to the `beacon-release` GitHub Environment. Repository administrators
must keep required reviewers configured there; changing the workflow file alone must not be used to
bypass an environment review.

## Building a release candidate

The cache-isolated Beacon CI build is the candidate builder. Each build attempt uploads
`beacon-javaagent-<attempt>` with the versioned JAR, SPDX SBOM, licenses, HTTP/Security verification
fixture, and `ci-evidence.json`. A separate small `beacon-ci-evidence-<attempt>` artifact allows
content matching without downloading every JAR. Candidates and evidence are retained for 30 days.
Only successful same-repository PR and manual runs are promotable; a main push's lightweight build
alone is not release validation. Re-running failed jobs can retain the earlier successful build
attempt, provided all selected jobs eventually succeed and its artifacts are still available.

Automatic lookup examines the latest 30 successful Beacon CI runs; older evidence may be supplied
by ID. Old runs produced before this artifact format cannot be promoted. If evidence is absent,
expired, from a fork, or for different content, run Beacon CI once on the release ref with the normal
profile (or select `full` when expanded coverage is intended), then publish using that run. Do not
manually upload a locally built substitute or silently fall back to an unvalidated release build.

For local diagnosis from a clean release checkout with JDK 25:

```bash
./gradlew :javaagent:assemble :javaagent:verifyBeaconAgent :javaagent:spdxSbom
./gradlew -p beacon/testing/security-smoke-fixture shadowJar
```

Local builds do not create promotable GitHub validation evidence. Publication attaches the exact
CI JAR, SHA-256 file, unchanged SPDX SBOM, provenance record, license, and third-party notices.

## Rollback and retry

A retry under the same version may publish only identical content. Stop if the tag or artifact differs from the expected value; do not overwrite existing assets. Retain traceability for a problematic release and roll back to the previous pinned artifact and its corresponding configuration.

## Build and initial launch

See the [contributing guide](../CONTRIBUTING.md) for build entry points and the [CI checklist](CI.md) for the initial GitHub launch and outstanding decisions. A successful ordinary `assemble` does not constitute release acceptance.

## Container distribution

After publishing a stable Agent release, run the separate
[container image workflow](docker/javaagent/README.md#build-and-release) to distribute that exact
JAR through GHCR. Images use the corresponding language version as their only tag and retain the
release's provenance and licenses. The native image tests and protected promotion job do not replace
the Agent release validation above.

# Beacon Java Release Process

Beacon uses an independent product version and artifact identity. The [packaging configuration](agent.gradle.kts) is loaded by `:javaagent`. Repository conditions prevent inherited official and legacy downstream publication jobs from serving as Beacon release entry points; see the [CI guide](CI.md). Beacon has separate [preparation](../.github/workflows/beacon-prepare-release.yml) and [publication](../.github/workflows/beacon-release.yml) workflows; neither calls inherited Maven, Sonatype, plugin, or image publication.

## Versioning and scope

- Beacon Java uses independent semantic versions and `vX.Y.Z` tags. Official upstream tags are fetched into the separate `refs/upstream-tags/` namespace and are not published as Beacon release tags.
- [version.properties](version.properties) is the only source of the product version. Stable releases use `X.Y.Z`, public release candidates use `X.Y.Z-rc.N`, and development versions use `X.Y.Z-SNAPSHOT`. Do not publish a SNAPSHOT as a formal release or override the release version through an ad hoc command-line property.
- The product version and [upstream baseline](upstream.lock.json) are recorded separately. Do not globally replace the upstream build version or modify the instrumented application's `service.version`.
- The complete installation package is `beacon-javaagent-<Beacon-version>.jar`. Helper artifacts such as `base` and `dontuse` are not published as Beacon installation packages. Do not publish the Beacon product through inherited Maven or Sonatype publication tasks.
- Manifest attributes `Implementation-Title`, `Implementation-Version`, and `Implementation-Vendor` identify the Beacon product. `Beacon-Upstream-Tag` and `Beacon-Upstream-Commit` identify the official baseline. `Beacon-Instrumentation-Version` retains the currently inherited module build version. Embedded files under `META-INF/beacon/` preserve version and provenance records.
- Do not bulk-rename upstream module coordinates, Java packages, or instrumentation scopes. The complete JAR's `java -jar` version output and AgentVersion read the Manifest and therefore use the Beacon product version; the module build version is available separately through `Beacon-Instrumentation-Version`. Existing startup log prefixes and the default `telemetry.distro.name` still come from inherited runtime code. Do not describe the file-name change as a complete rebranding of all runtime identifiers.
- State the functionality and support scope actually validated for each release. The current Profiling implementation is inherited and experimental. Its conversion to an Extension is a separate effort and is not a prerequisite for the initial source publication.
- Publish source provenance, licenses, required third-party notices, artifact digests, SPDX SBOM,
  and known limitations with each release. GitHub Releases is the current artifact host, and the
  publication workflow creates GitHub build-provenance attestations through OIDC.

## Release sequence

1. Add user-visible changes under `Unreleased`. Run **Prepare Beacon release** from `main` with the target version. It updates `version.properties`, moves the completed changelog entries, opens a release pull request, and requests full Beacon CI. Do not mix upstream changelog entries into the Beacon changelog. The same two files may be updated manually in an exceptional recovery, but must still be reviewed in a pull request.
2. Merge the release pull request, then run [Beacon CI manual extended validation](CI.md#extended-validation-and-test-images) with `full` selected against the exact merge commit. Record the successful workflow run ID. Add Windows, OpenJ9, performance, or other targeted testing according to the declared support scope.
3. Run **Beacon release** against that same Git ref, supplying the committed version and full-validation run ID. The workflow rejects a different commit, a reduced matrix, an existing release, or inconsistent metadata. It builds the candidate with dependency caches disabled and records its SHA-256 digest and provenance.
4. The candidate job runs packaged-Agent and embedded-Security smoke tests. The `beacon-release` GitHub Environment gates the publish job. After approval, that job downloads the candidate artifact from the first job, revalidates its digest and Manifest, creates an annotated immutable tag, publishes the exact JAR without rebuilding, and downloads the public assets for another validation pass.
5. If the product version, Manifest, or any artifact content changes, rebuild and validate again. A public release candidate whose content differs from the stable release cannot simply be renamed as the same artifact.
6. Link user documentation and the support scope to the version. For the first release or when entry points or support status change, update the [Beacon product repository](https://github.com/beacon-observability/beacon). Cross-repository registration is not required for every patch release.

The publish job is bound to the `beacon-release` GitHub Environment. Repository administrators
must keep required reviewers configured there; changing the workflow file alone must not be used to
bypass an environment review.

## Building a release candidate

The publication workflow is the formal candidate builder. For local diagnosis from a clean release
commit with JDK 21, run the following commands at the repository root:

```bash
./gradlew :javaagent:assemble :javaagent:verifyBeaconAgent :javaagent:spdxSbom
./gradlew -p beacon/testing/security-smoke-fixture shadowJar
```

Output is written to `javaagent/build/libs/`, `javaagent/build/spdx/`, and the fixture's `build/libs/` directory. Select the single complete agent that matches the committed product version; do not publish through a wildcard that may include stale artifacts. `verifyBeaconAgent` checks the file name, Manifest, and provenance files, but does not replace functional, compatibility, or performance testing.

Do not manually upload a locally built substitute. The publication workflow attaches the exact
candidate JAR, SHA-256 file, SPDX SBOM, provenance record, license, and third-party notices. Set the
next development version in a separate commit; it must not be included in the current release tag.

## Rollback and retry

A retry under the same version may publish only identical content. Stop if the tag or artifact differs from the expected value; do not overwrite existing assets. Retain traceability for a problematic release and roll back to the previous pinned artifact and its corresponding configuration.

## Build and initial launch

See the [contributing guide](../CONTRIBUTING.md) for build entry points and the [CI checklist](CI.md) for the initial GitHub launch and outstanding decisions. A successful ordinary `assemble` does not constitute release acceptance.

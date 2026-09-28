# Beacon Java Release Process

Beacon uses an independent product version and artifact identity. The [packaging configuration](agent.gradle.kts) is loaded by `:javaagent`. Repository conditions prevent inherited official and legacy downstream publication jobs from serving as Beacon release entry points; see the [CI guide](CI.md). The controlled build and manual publication process below does not depend on unconfigured automated publication jobs.

## Versioning and scope

- Beacon Java uses independent semantic versions and `beacon-vX.Y.Z` tags. It does not reuse legacy `v*` tags.
- [version.properties](version.properties) is the only source of the product version. Stable releases use `X.Y.Z`, public release candidates use `X.Y.Z-rc.N`, and development versions use `X.Y.Z-SNAPSHOT`. Do not publish a SNAPSHOT as a formal release or override the release version through an ad hoc command-line property.
- The product version and [upstream baseline](upstream.lock.json) are recorded separately. Do not globally replace the upstream build version or modify the instrumented application's `service.version`.
- The complete installation package is `beacon-javaagent-<Beacon-version>.jar`. Helper artifacts such as `base` and `dontuse` are not published as Beacon installation packages. Do not publish the Beacon product through inherited Maven or Sonatype publication tasks.
- Manifest attributes `Implementation-Title`, `Implementation-Version`, and `Implementation-Vendor` identify the Beacon product. `Beacon-Upstream-Tag` and `Beacon-Upstream-Commit` identify the official baseline. `Beacon-Instrumentation-Version` retains the currently inherited module build version. Embedded files under `META-INF/beacon/` preserve version and provenance records.
- Do not bulk-rename upstream module coordinates, Java packages, or instrumentation scopes. The complete JAR's `java -jar` version output and AgentVersion read the Manifest and therefore use the Beacon product version; the module build version is available separately through `Beacon-Instrumentation-Version`. Existing startup log prefixes and the default `telemetry.distro.name` still come from inherited runtime code. Do not describe the file-name change as a complete rebranding of all runtime identifiers.
- State the functionality and support scope actually validated for each release. The current Profiling implementation is inherited and experimental. Its conversion to an Extension is a separate effort and is not a prerequisite for the initial source publication.
- Publish source provenance, licenses, required third-party notices, artifact digests, and known limitations with each release. Define signing, artifact hosting, and SBOM generation in the publication implementation.

## Release sequence

1. In a release pull request, update `version.properties`, move completed entries in the [Changelog](CHANGELOG.md) into the target version, and state configuration changes, publication scope, and notes. After merge, pin the final source commit. Do not mix upstream changelog entries into the Beacon changelog.
2. Build the release candidate from that commit with pinned dependencies and a pinned build environment, and record its SHA-256 digest and build provenance.
3. Complete applicable module, runtime, Beacon enhancement, receiver, performance, and rollback validation against that exact candidate. Run [Beacon CI manual extended validation](CI.md#extended-validation-and-test-images) and add Windows, OpenJ9, performance, or other targeted testing according to the declared support scope. Extended CI does not replace candidate acceptance. Bind test evidence to the same commit and artifact digest.
4. After approval, create an immutable release tag at the validated commit and publish the same validated artifact. Do not change dependencies or rebuild a substitute at this step.
5. If the product version, Manifest, or any artifact content changes, rebuild and validate again. A public release candidate whose content differs from the stable release cannot simply be renamed as the same artifact.
6. Link user documentation and the support scope to the version. For the first release or when entry points or support status change, update the [Beacon product repository](https://github.com/beacon-observability/beacon). Cross-repository registration is not required for every patch release.

This process is not yet bound to a specific GitHub Environment or approver. Configure those controls after administrator confirmation; documentation alone does not make approval enforcement active.

## Building a release candidate

From a clean release commit with JDK 21, run the following command at the repository root:

```bash
./gradlew :javaagent:assemble :javaagent:verifyBeaconAgent
```

Output is written to `javaagent/build/libs/`. Select the single complete agent that matches the committed product version; do not publish through a wildcard that may include stale artifacts. `verifyBeaconAgent` checks the file name, Manifest, and provenance files, but does not replace functional, compatibility, or performance testing. Preserve the SHA-256 digest, source commit, and validation results with the candidate.

After approval, push only that version's `beacon-vX.Y.Z` tag and upload the same validated JAR, SHA-256 digest, and required notices to a Release with the same name. Do not use `git push --tags`, and do not rebuild and replace the candidate. Set the next development version in a separate commit; it must not be included in the current release tag.

## Rollback and retry

A retry under the same version may publish only identical content. Stop if the tag or artifact differs from the expected value; do not overwrite existing assets. Retain traceability for a problematic release and roll back to the previous pinned artifact and its corresponding configuration.

## Build and initial launch

See the [contributing guide](../CONTRIBUTING.md) for build entry points and the [CI checklist](CI.md) for the initial GitHub launch and outstanding decisions. A successful ordinary `assemble` does not constitute release acceptance.

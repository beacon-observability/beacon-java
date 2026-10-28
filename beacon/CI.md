# CI and Initial Launch Checklist

## Branches and check entry points

The product development branch is `main`. [Beacon CI](../.github/workflows/beacon-ci.yml) is this repository's entry point for pull-request, main-branch push, and manual validation. It runs only in `beacon-observability/beacon-java` for pull requests targeting `main` or `release/*`.

| Scenario | Module test matrix | Additional checks |
| --- | --- | --- |
| Regular pull request | JDK 21 × 4 partitions × 2 Indy modes, for 8 test jobs | 4 Muzzle partitions when instrumentation directories change |
| Upstream synchronization, shared build, or agent core changes | JDK 8 with classic transformation, JDK 17 with Indy, and JDK 21 with both modes, each across 4 partitions, for 16 test jobs | 4 Muzzle partitions |
| Manual `full` selection | JDK 8/11/17/21/25/26 × 4 partitions × 2 Indy modes, for 48 test jobs | Muzzle, latest-dependency tests, and upstream Linux container smoke tests |

All three pull-request and manual tiers build the complete agent; validate the Beacon file name, Manifest, and provenance; run maintainer-script and packaging regression tests; run packaged-agent HTTP instrumentation, TraceContext, OTLP trace export, and embedded-Security smoke tests; run the JDK 21 / Spring Boot 3.5.7 packaged-agent JDBC regression against PostgreSQL 16.15 with Trace, Logs, Metrics, and Security combinations; and run formatting, package-name, other static checks, and license-list checks. Module tests use `listBeaconTestsInPartition`, preserving upstream's four project partitions and separate smoke/aggregate exclusions. It realizes registered Test tasks directly after project configuration, including late and detached tasks, without resolving the full `check` dependency graph or executing tests. Tests wired into Gradle for Beacon-specific enhancements are included. A module without tests does not automatically gain functional acceptance.

After a pull request has passed its selected tier and is merged, the `main` push runs only the clean agent build, packaging verification, and packaged-agent smoke test. The merge ruleset prevents direct pushes, so repeating the complete pull-request matrix on the resulting merge commit would add substantial latency without testing different file content. Manual `full` validation remains available when release acceptance or an explicit post-merge rerun is required.

The [planning script](scripts/ci-plan.cjs) selects a tier from the complete Git diff rather than branch names or pull-request labels. Pull requests compare the base SHA with GitHub's default checked-out merge result; pushes compare the before SHA with the current commit. A missing baseline expands validation to the upgrade tier, while an unreadable otherwise-valid SHA fails rather than silently reducing coverage. Changes to settings, baselines, dependencies, shared test infrastructure, or CI itself expand the matrix. The script and its tests define the exact path rules.

At most 16 matrix jobs run concurrently, subject to available GitHub runner capacity. The full
48-job matrix therefore needs at least three batches. A new commit cancels an older Beacon CI run
for the same pull request. It does not automatically cancel upstream workflows that began before migration.

Beacon test jobs set `testShowStandardStreams=false` to avoid streaming successful tests' verbose
Agent DEBUG output. Full per-test stdout/stderr remains in the uploaded JUnit XML and HTML reports;
test failures and full exception details still appear in the console. Local Gradle runs retain
standard-stream logging unless this property is explicitly set.

Wrapper validation, path-triggered metadata checks, dependency review, CodeQL, and workflow security scans continue to run independently and are not included in the test-job counts above. `Beacon required` does not replace them; configure them separately as required checks when appropriate.

### Merge gate

`Beacon required` summarizes the checks selected for the current change. Collector changes and manual
full runs also compare all four direct-discovery partitions against an independent snapshot from the
legacy `check` graph. Missing or duplicated tests fail the gate; additional registered tests are
listed in the uploaded coverage report. A required job that fails, is canceled, or is unexpectedly skipped prevents the gate from passing; only optional jobs that were not selected may be skipped. The GitHub Ruleset for `main` requires this check and currently does not require pull-request approval. Editing workflow files does not automatically update GitHub branch protection.

Fix the cause of a failing check; do not remove checks solely to obtain a green status. CI artifacts are development artifacts, not formal releases, and a successful build does not replace functional or release acceptance.

The artifact-producing build disables Node package-manager and Gradle user-home caches so restored content cannot enter the downloadable agent. Quality, module-test, and upstream-smoke jobs may restore Gradle caches read-only because they upload only reports, not runtime artifacts. Formal release candidates must continue to come from the cache-isolated build path.

[Warm Beacon test caches](../.github/workflows/beacon-test-cache.yml) refreshes those read-only
test caches after a push to trusted `main`, daily, or a manual dispatch on `main`. It downloads
external dependency files for every JVM source set's compile, runtime, and annotation processor
classpaths, once for baseline dependencies and once for pinned latest dependencies. Project outputs
are excluded from dependency warming; the shared test Agent is then built into the local build cache.
Resolving metadata or listing disabled tests alone does not guarantee that dependency JARs are cached.
Future test runners can restore
current configuration, dependencies, and shared test infrastructure. This workflow runs
no test suite, uploads no Agent, and does not serve as release acceptance. After merging CI or
dependency changes, let this warmer finish before launching a manual full validation.

Cache hits restore existing files rather than redownloading every dependency from Maven. Missing
artifacts, changed versions, and expired dynamic-version metadata can still require network access.
The first warm run must populate the cache; read-only test consumers cannot save newly downloaded
artifacts. Cache refresh failures remain visible and must be corrected. Cache warming does not
eliminate test execution or guarantee that every tool or container image is cached.
Each warm run uses a unique matrix value in setup-gradle's cache key, so daily/manual refreshes
can save a new immutable snapshot even when the source commit has not changed.
The Gradle distribution is cached as well. If it is missing, the wrapper allows a 60-second
network timeout and three retries for the initial download, while retaining SHA-256 verification.

### Extended validation and test images

In Actions → Beacon CI → Run workflow, select the branch to validate and choose `full` for extended validation. Choose `native` to additionally invoke GraalVM Native tests. The workflow must first exist on the default branch before it can be launched from the Actions page. No scheduled full run is currently added, to avoid continuously consuming runners by default.

Here, `full` means the extended set defined above, not every upstream job. Windows, OpenJ9, performance, example-project, and Gradle-plugin validation must still be scheduled according to the actual release support scope and cannot be claimed as supported on this basis. Full container smoke tests use the upstream image versions pinned in the source tree and require Docker plus access to those images. If an image is unavailable, fix its source and rerun; do not ignore the failure.

Inherited pull-request image builds run only in the upstream repository. Regular Beacon pull requests use the [packaged-agent smoke test](scripts/agent-smoke.cjs), which requires no container images, and do not rebuild Payara, Tomcat, Play, gRPC, early-JDK8, or similar images. Before changing test images in the future, establish Beacon-owned image build and hosting processes. Skipping image builds must not be treated as acceptance of image changes.

### JDBC and combined-feature regression

The standalone [JDBC fixture](testing/jdbc-smoke) starts the complete Agent through `-javaagent`,
executes parameterized SQL through JdbcTemplate, and decodes OTLP HTTP/protobuf at a local receiver.
It checks PostgreSQL client span counts, database attributes, JDBC instrumentation scope, and HTTP
parentage in four configurations: Trace, Trace + Logs + Metrics, Trace + Security, and all features.
Enabled logs, metrics, Security health, and runtime SBOM must also be observed. This test requires
JDK 21 and Docker; it runs in the build job for every Beacon CI tier.

```bash
version=$(sed -n 's/^version=//p' beacon/version.properties)
./gradlew -p beacon/testing/jdbc-smoke test \
  "-PagentPath=$PWD/javaagent/build/libs/beacon-javaagent-$version.jar"
```

`agentPath` can also point to a downloaded released agent for reproduction. This fixture validates
agent creation and OTLP reception; it does not validate DataKit-specific mapping or replace the
original benchmark's throughput, duration, and performance acceptance.

## Isolation of inherited workflows

Job-level repository conditions restrict inherited main-branch and pull-request matrices, pull-request image builds, formal release, snapshot and image publication, automated dependency and source changes, Issue and pull-request management bots, and unadapted scheduled tasks to the original OpenTelemetry repository. The old downstream release process remains disabled. Reusable Muzzle, latest-dependency, and Native test implementations remain available and are invoked by Beacon under the rules above.

These restrictions preserve the original job implementations and their existing conditions; they do not rely on missing secrets to prevent execution. Restricted jobs are skipped in Beacon and ordinary downstream repositories, although their workflows or skipped runs may remain visible in the UI. Inherited FOSSA configuration generation and upstream bot lock-file regeneration checks are not Beacon merge gates. License-list and workflow security checks remain enabled.

Reusable inherited release and failure-notification jobs are also restricted. CodeQL scanning remains enabled, while its inherited scheduled-failure Issue notification runs only upstream. Beacon uses its own manually dispatched preparation and release workflows; it has not enabled automated upstream upgrades or inherited pull-request and Issue management bots.

Inherited `*.lock.yml` generated files are also protected by repository conditions. When regenerating or merging upstream versions, review those conditions again; do not overwrite them with generated output that re-enables the jobs. Adapt workflows individually as needed rather than removing repository restrictions wholesale.

## Initial GitHub launch

1. Verify the target repository, visibility, and Actions policy. Keep Actions disabled before the first push, or first review the workflows that will be allowed to execute.
2. Push only the prepared `main` development branch and set the remote default branch to `main`. Do not blindly push old branches or all historical tags.
3. Enable the required test workflows and run one pull-request and one main-branch build to confirm that dependencies, runners, networking, and check permissions work.
4. The maintainers are `@lrwh` and `@songlonqi-java`. Maintain them in [CODEOWNERS](../.github/CODEOWNERS), and verify both accounts' repository permissions and the `main` Ruleset.
5. Confirm that workflow and documentation links are accessible with the intended readers' permissions, and update the pending-release status in the [Beacon product repository](https://github.com/beacon-observability/beacon).

## Items still to confirm

- Long-term artifact hosting and signing policy beyond GitHub Releases and GitHub's OIDC-backed
  build-provenance attestation. The product version, file name, and Manifest are managed by the
  [Beacon packaging configuration](agent.gradle.kts).
- The actual support matrix and build and runtime acceptance results.

Until these items are complete, do not expand support claims beyond the evidence attached to each published release. See the [release process](RELEASING.md) for publication order.

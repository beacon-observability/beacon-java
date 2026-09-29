# CI and Initial Launch Checklist

## Branches and check entry points

The product development branch is `main`. [Beacon CI](../.github/workflows/beacon-ci.yml) is this repository's entry point for pull-request, main-branch push, and manual validation. It runs only in `beacon-observability/beacon-java` for pull requests targeting `main` or `release/*`.

| Scenario | Module test matrix | Additional checks |
| --- | --- | --- |
| Regular pull request | JDK 21 × 4 partitions × 2 Indy modes, for 8 test jobs | 4 Muzzle partitions when instrumentation directories change |
| Upstream synchronization, shared build, or agent core changes | JDK 8 with classic transformation, JDK 17 with Indy, and JDK 21 with both modes, each across 4 partitions, for 16 test jobs | 4 Muzzle partitions |
| Manual `full` selection | JDK 8/11/17/21/25/26 × 4 partitions × 2 Indy modes, for 48 test jobs | Muzzle, latest-dependency tests, and upstream Linux container smoke tests |

All three pull-request and manual tiers build the complete agent; validate the Beacon file name, Manifest, and provenance; run maintainer-script and packaging regression tests; run packaged-agent HTTP instrumentation, TraceContext, and OTLP trace export smoke tests; and run formatting, package-name, other static checks, and license-list checks. Module tests reuse upstream `listTestsInPartition` without excluding test modules by directory. Tests wired into Gradle for Beacon-specific enhancements are included. A module without tests does not automatically gain functional acceptance.

After a pull request has passed its selected tier and is merged, the `main` push runs only the clean agent build, packaging verification, and packaged-agent smoke test. The merge ruleset prevents direct pushes, so repeating the complete pull-request matrix on the resulting merge commit would add substantial latency without testing different file content. Manual `full` validation remains available when release acceptance or an explicit post-merge rerun is required.

The [planning script](scripts/ci-plan.cjs) selects a tier from the complete Git diff rather than branch names or pull-request labels. Pull requests compare the base SHA with GitHub's default checked-out merge result; pushes compare the before SHA with the current commit. A missing baseline expands validation to the upgrade tier, while an unreadable otherwise-valid SHA fails rather than silently reducing coverage. Changes to settings, baselines, dependencies, shared test infrastructure, or CI itself expand the matrix. The script and its tests define the exact path rules.

At most eight matrix jobs run concurrently. A new commit cancels an older Beacon CI run for the same pull request. It does not automatically cancel upstream workflows that began before migration.

Wrapper validation, path-triggered metadata checks, dependency review, CodeQL, and workflow security scans continue to run independently and are not included in the test-job counts above. `Beacon required` does not replace them; configure them separately as required checks when appropriate.

### Merge gate

`Beacon required` summarizes the checks selected for the current change. A required job that fails, is canceled, or is unexpectedly skipped prevents the gate from passing; only optional jobs that were not selected may be skipped. The GitHub Ruleset for `main` requires this check and currently does not require pull-request approval. Editing workflow files does not automatically update GitHub branch protection.

Fix the cause of a failing check; do not remove checks solely to obtain a green status. CI artifacts are development artifacts, not formal releases, and a successful build does not replace functional or release acceptance.

The artifact-producing build disables Node package-manager and Gradle user-home caches so restored content cannot enter the downloadable agent. Quality, module-test, and upstream-smoke jobs may restore Gradle caches read-only because they upload only reports, not runtime artifacts. Formal release candidates must continue to come from the cache-isolated build path.

### Extended validation and test images

In Actions → Beacon CI → Run workflow, select the branch to validate and choose `full` for extended validation. Choose `native` to additionally invoke GraalVM Native tests. The workflow must first exist on the default branch before it can be launched from the Actions page. No scheduled full run is currently added, to avoid continuously consuming runners by default.

Here, `full` means the extended set defined above, not every upstream job. Windows, OpenJ9, performance, example-project, and Gradle-plugin validation must still be scheduled according to the actual release support scope and cannot be claimed as supported on this basis. Full container smoke tests use the upstream image versions pinned in the source tree and require Docker plus access to those images. If an image is unavailable, fix its source and rerun; do not ignore the failure.

Inherited pull-request image builds run only in the upstream repository. Regular Beacon pull requests use the [packaged-agent smoke test](scripts/agent-smoke.cjs), which requires no container images, and do not rebuild Payara, Tomcat, Play, gRPC, early-JDK8, or similar images. Before changing test images in the future, establish Beacon-owned image build and hosting processes. Skipping image builds must not be treated as acceptance of image changes.

## Isolation of inherited workflows

Job-level repository conditions restrict inherited main-branch and pull-request matrices, pull-request image builds, formal release, snapshot and image publication, automated dependency and source changes, Issue and pull-request management bots, and unadapted scheduled tasks to the original OpenTelemetry repository. The old downstream release process remains disabled. Reusable Muzzle, latest-dependency, and Native test implementations remain available and are invoked by Beacon under the rules above.

These restrictions preserve the original job implementations and their existing conditions; they do not rely on missing secrets to prevent execution. Restricted jobs are skipped in Beacon and ordinary downstream repositories, although their workflows or skipped runs may remain visible in the UI. Inherited FOSSA configuration generation and upstream bot lock-file regeneration checks are not Beacon merge gates. License-list and workflow security checks remain enabled.

Reusable release and failure-notification jobs are also restricted. CodeQL scanning remains enabled, while its inherited scheduled-failure Issue notification runs only upstream. Beacon has not enabled automated releases, automated upstream upgrades, or pull-request and Issue management bots.

Inherited `*.lock.yml` generated files are also protected by repository conditions. When regenerating or merging upstream versions, review those conditions again; do not overwrite them with generated output that re-enables the jobs. Adapt workflows individually as needed rather than removing repository restrictions wholesale.

## Initial GitHub launch

1. Verify the target repository, visibility, and Actions policy. Keep Actions disabled before the first push, or first review the workflows that will be allowed to execute.
2. Push only the prepared `main` development branch and set the remote default branch to `main`. Do not blindly push old branches or all historical tags.
3. Enable the required test workflows and run one pull-request and one main-branch build to confirm that dependencies, runners, networking, and check permissions work.
4. The maintainers are `@lrwh` and `@songlonqi-java`. Maintain them in [CODEOWNERS](../.github/CODEOWNERS), and verify both accounts' repository permissions and the `main` Ruleset.
5. Confirm that workflow and documentation links are accessible with the intended readers' permissions, and update the pending-release status in the [Beacon product repository](https://github.com/beacon-observability/beacon).

## Items still to confirm

- Formal release approvers and a GitHub Environment. `main` does not currently require code-owner approval.
- Long-term artifact hosting and signing policy. GitHub Releases currently hosts the release JAR and SHA-256 digest. The product version, file name, and Manifest are managed by the [Beacon packaging configuration](agent.gradle.kts).
- The actual support matrix and build and runtime acceptance results.

Until these items are complete, do not expand support claims beyond the evidence attached to each published release. See the [release process](RELEASING.md) for publication order.

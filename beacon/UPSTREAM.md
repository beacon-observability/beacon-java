# Synchronizing OpenTelemetry

Run every command from the repository root. The development branch is `main`. Keep the import record in the [baseline file](upstream.lock.json) unchanged, and update the upstream record only after the target version has actually been integrated.

## Initial setup

After a full clone of the Beacon repository, `origin` should point to `https://github.com/beacon-observability/beacon-java.git`. Verify it with `git remote -v`. Add `upstream` only if it does not already exist:

```bash
git remote add upstream https://github.com/open-telemetry/opentelemetry-java-instrumentation.git
```

If it already exists, verify its URL instead of adding it again or overwriting it without review. Then configure it:

```bash
git config remote.upstream.tagOpt --no-tags
git config --replace-all remote.upstream.fetch '+refs/heads/main:refs/remotes/upstream/main'
git config remote.pushDefault origin
```

This configuration replaces the old automatic tag-fetch rules and fetches only the official main branch. Fetch custom upstream tags through the validation script described below. `git fetch upstream` does not update adopted tag references.

Historical import commits are retained in this repository and can be queried directly by the commit SHA recorded in the baseline file. Remotes, refspecs, and fetched remote-tracking references are local configuration and are not transferred with commits; CI must configure them explicitly as well. Do not push every historical branch or tag as a Beacon release entry point.

## Fetching and validating a stable tag

After selecting an official Release, review its contents and pin the full commit SHA referenced by the tag. Do not use a single automated command that fetches an arbitrary SHA and then trusts it without review.

```bash
# This only demonstrates validation of the currently recorded baseline.
# For an upgrade, use the tag and commit approved during review.
bash beacon/scripts/fetch-upstream-tag.sh \
  v2.31.1 8ad06a082e051f366f19c16ad95a7b68edf30afd
```

The [fetch script](scripts/fetch-upstream-tag.sh) fetches one tag into a temporary reference and verifies that it points to the specified commit. If a local upstream reference with the same name already exists, it also compares the complete tag object and rejects rewrites. Only after every check passes does it update `refs/upstream-tags/<tag>`. The script does not merge code, update the baseline file, or create a formal release tag.

Git does not give `refs/upstream-tags/*` the same rewrite rejection behavior as `refs/tags/*`, so omitting `+` from the refspec is insufficient. The script validates object identity but does not replace trusted-source review or signature verification. See the [Git fetch rules](https://git-scm.com/docs/git-fetch).

## Integrating a validated target

1. Confirm that the working tree is clean and update the product main branch. `origin/main` exists only after the first push.
2. Complete the tag-fetch validation above, then merge the pinned commit on a synchronization branch.
3. Resolve conflicts and complete adaptations. Update the upstream tag and commit in the baseline file, and record the upgrade and user impact under `Unreleased` in the [Beacon Changelog](CHANGELOG.md). Do not create a separate delta ledger.
4. Run affected module tests, Muzzle, the agent smoke test, and Beacon enhancement regression tests. Validate data and runtime compatibility according to the release scope.
5. After committing the merge, verify ancestry and create a pull request targeting `main`.

The following is an operation template. Replace every placeholder first, and use a target SHA from a completed review record:

```bash
git switch main
git fetch --no-tags origin
git merge --ff-only origin/main

OTEL_TARGET_TAG='vX.Y.Z'
OTEL_TARGET_COMMIT='<full-reviewed-commit-SHA>'
bash beacon/scripts/fetch-upstream-tag.sh "$OTEL_TARGET_TAG" "$OTEL_TARGET_COMMIT" &&
  git switch -c "sync/otel-${OTEL_TARGET_TAG}" &&
  git merge --no-ff --no-commit "$OTEL_TARGET_COMMIT"
```

At the `--no-commit` stage, no merge commit exists, so do not test whether the target is already an ancestor of the current HEAD. After resolving conflicts, testing, and committing, run:

```bash
git merge-base --is-ancestor "$OTEL_TARGET_COMMIT" HEAD
```

The exit code must be zero. If the target is already an ancestor, no repeated upgrade is needed. Preserve upstream history when merging the synchronization pull request into the product main branch; do not squash the entire synchronization. If the merge cannot continue, confirm that no conflict-resolution work needs to be retained before using `git merge --abort`.

## Dependency and release boundaries

Prefer the SDK, BOM, and build constraints associated with the target upstream version. Do not treat independently upgrading every dependency to its latest version as compatibility. Evaluate and validate security patches separately.

Fetched, merged, tested, and released are distinct states. The baseline file records source provenance, test evidence belongs to the corresponding commit's pull request and CI, and publication results belong to the pinned version's Release.

Synchronization does not automatically change the [Beacon product version](version.properties), and the upstream version is not the Beacon release version. Retain the root upstream changelog. During merges, verify that `javaagent/build.gradle.kts` still loads the [Beacon packaging configuration](agent.gradle.kts) and that CI still uploads the Beacon artifact path.

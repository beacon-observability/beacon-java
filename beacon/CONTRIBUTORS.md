# Beacon Java Contributors

Beacon Java retains the complete OpenTelemetry Java Instrumentation commit history so that source provenance can be traced through Git log, blame, and commit links. The GitHub Contributors graph may therefore include upstream authors and must not be treated as the Beacon project membership list. This file separately records verified contributors to the historical downstream and Beacon-specific work. It does not replace Git history or license attribution and does not imply repository administration privileges.

## Verified contributors

| GitHub account | Historical Git signatures | Traceable downstream contribution examples |
| --- | --- | --- |
| [@lrwh](https://github.com/lrwh) | `liurui`, `Xinyou Qianqianjie` | [Beacon project initialization](https://github.com/beacon-observability/beacon-java/commit/28b06d9ba60361dd7ab47c198243c16f9a80d02e), [experimental Profiling](https://github.com/beacon-observability/beacon-java/commit/ed3c0eea74) |
| [@songlonqi-java](https://github.com/songlonqi-java) | `songlq` | [JDBC SQL redaction](https://github.com/beacon-observability/beacon-java/commit/50d181fa17), [historical HSF instrumentation](https://github.com/beacon-observability/beacon-java/commit/6687592826) |

The list is based on GitHub's association of the accounts with the cited commit authors and a review of actual downstream changes. Multiple Git signatures for the same account are consolidated into one person. HSF has been removed from the current agent, but its historical commits remain, so the associated contribution remains credited.

## Maintenance rules

- When a Beacon-specific pull request is merged into `main` and introduces a new contributor, add the account, Git signature, and at least one accessible commit or pull-request link in the same pull request or an immediately following documentation pull request. Update the root README avatar and account at the same time. If a Git signature is known but the account cannot be confirmed, retain the signature and evidence without guessing the identity.
- Preserve official upstream commits and authors when synchronizing upstream versions. Do not automatically add upstream authors to this list merely because their history was merged. An upstream author who directly contributes Beacon-specific work may be added under the preceding rule.
- Submit evidence in a pull request when correcting aliases, omissions, or attribution. This list only distinguishes Beacon-specific contributions and does not modify original commit authorship.

The complete commit chain remains authoritative in the `main` Git history. As of 2026-09-22, the two contributors above have been verified; update this list as the project evolves.

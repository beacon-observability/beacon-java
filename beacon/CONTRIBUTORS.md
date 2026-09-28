# Beacon Java 自有贡献者

Beacon Java 保留完整的 OpenTelemetry Java Instrumentation 提交历史，以便使用 Git Log、Blame 和提交链接追溯代码来源。因此 GitHub 的 Contributors 图表可能同时列出上游作者，不能直接当作 Beacon 项目成员名单。本文件单独记录已核对身份的既有下游与 Beacon 自有贡献者；不替代 Git 历史、许可证署名，也不表示仓库管理权限。

## 已核对名单

| GitHub 账号 | 历史 Git 署名 | 可追溯的下游贡献示例 |
| --- | --- | --- |
| [@lrwh](https://github.com/lrwh) | `liurui`、`心有千千结` | [Beacon 工程初始化](https://github.com/beacon-observability/beacon-java/commit/28b06d9ba60361dd7ab47c198243c16f9a80d02e)、[实验性 Profiling](https://github.com/beacon-observability/beacon-java/commit/ed3c0eea74) |
| [@songlonqi-java](https://github.com/songlonqi-java) | `songlq` | [JDBC SQL 脱敏](https://github.com/beacon-observability/beacon-java/commit/50d181fa17)、[历史 HSF 插桩](https://github.com/beacon-observability/beacon-java/commit/6687592826) |

名单依据 GitHub 对上述提交作者账号的关联以及实际下游改动核对；同一账号的不同 Git 署名合并为一人。HSF 当前已从 Agent 移除，但其历史提交仍保留，历史贡献不会因此删除。

## 维护规则

- Beacon 自有 PR 合入 `main` 时，如产生新的贡献者，在同一 PR 或紧随其后的文档 PR 中补充账号、Git 署名和至少一个可访问的提交或 PR 链接，并同步更新根目录 README 的头像与账号。仅有 Git 署名而无法确认账号时先保留署名与证据，不猜测身份。
- 同步上游版本时保留官方原始提交和作者，不因合入上游历史而自动把官方作者加入本名单。上游作者若直接提交 Beacon 专有改动，可按上一条加入。
- 对别名、遗漏或归属的修正通过 PR 提交证据。名单只用于区分 Beacon 自有贡献，不修改原始提交的作者信息。

完整提交链仍以 `main` 的 Git 历史为准；本名单截至 2026-09-22 已核对上述两位贡献者，后续随项目维护更新。

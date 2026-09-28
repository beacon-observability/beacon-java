# 同步 OpenTelemetry

所有命令均从仓库根目录执行。开发分支为 `main`；[基线文件](upstream.lock.json)中的导入记录保持不变，上游记录只在实际合入目标版本后更新。

## 首次配置

从 Beacon 仓库完整克隆后，`origin` 应指向 `https://github.com/beacon-observability/beacon-java.git`。先用 `git remote -v` 核对。不存在 `upstream` 时再添加：

```bash
git remote add upstream https://github.com/open-telemetry/opentelemetry-java-instrumentation.git
```

若已存在，先核对地址，不要重复添加或未经检查覆盖。确认后配置：

```bash
git config remote.upstream.tagOpt --no-tags
git config --replace-all remote.upstream.fetch '+refs/heads/main:refs/remotes/upstream/main'
git config remote.pushDefault origin
```

此配置替换旧的自动标签抓取规则，仅抓取官方主线。自定义上游标签必须通过下文的校验脚本获取。`git fetch upstream` 不会更新已采用的标签引用。

历史导入提交已经保留在当前仓库，可直接使用基线文件记录的提交 SHA 查询。Remote、refspec 和抓取产生的远程跟踪引用属于本地配置，不随提交传递；CI 也必须显式配置。不要把所有历史分支或标签直接推送成 Beacon 的发布入口。

## 获取并校验正式标签

选定官方 Release 后，审查发布内容并固定该标签对应的完整提交 SHA。不能在同一条自动命令中抓到什么 SHA 就无条件信任什么 SHA。

```bash
# 仅示范如何核对当前已登记基线；升级时换成评审确定的标签与提交。
bash beacon/scripts/fetch-upstream-tag.sh \
  v2.31.1 8ad06a082e051f366f19c16ad95a7b68edf30afd
```

[抓取脚本](scripts/fetch-upstream-tag.sh)将单个标签抓入临时引用，检查它确实指向指定提交；若同名本地上游引用已存在，还会比较完整标签对象，拒绝改写。只有全部通过，才更新 `refs/upstream-tags/<tag>`。脚本不会合并代码、修改基线文件或创建正式发行标签。

Git 对 `refs/upstream-tags/*` 不提供与 `refs/tags/*` 相同的拒绝改写规则，因此不能仅依赖 refspec 不带 `+`。此脚本校验对象一致性，不替代可信来源审查或签名验证。[Git fetch 规则](https://git-scm.com/docs/git-fetch)

## 合入已核对的目标

1. 确认工作区干净，更新产品主线；首次推送后才会有 `origin/main`。
2. 完成上述标签抓取校验，在同步分支合并固定提交。
3. 解决冲突、补齐适配，更新基线文件的上游标签与提交，在 [Beacon Changelog](CHANGELOG.md) 的 `Unreleased` 记录升级及用户影响；不另建差异台账。
4. 运行受影响模块、Muzzle、Agent 烟测和自有增强回归；按发布范围验证数据与运行环境兼容性。
5. 提交合并后验证祖先关系，创建目标为 `main` 的 PR。

以下为操作模板，占位值必须先替换，目标 SHA 应来自已完成评审的记录：

```bash
git switch main
git fetch --no-tags origin
git merge --ff-only origin/main

OTEL_TARGET_TAG='vX.Y.Z'
OTEL_TARGET_COMMIT='<完整的已核对提交SHA>'
bash beacon/scripts/fetch-upstream-tag.sh "$OTEL_TARGET_TAG" "$OTEL_TARGET_COMMIT" &&
  git switch -c "sync/otel-${OTEL_TARGET_TAG}" &&
  git merge --no-ff --no-commit "$OTEL_TARGET_COMMIT"
```

`--no-commit` 阶段尚未创建合并提交，不能用当前 HEAD 已包含目标祖先作为判断。完成冲突处理、测试并提交后，再运行：

```bash
git merge-base --is-ancestor "$OTEL_TARGET_COMMIT" HEAD
```

退出码必须为 0。若目标早已是祖先，不需要重复升级。同步 PR 合入产品主线时保留上游历史，不 squash 整次同步；无法继续时，确认没有需要保留的冲突解决工作再使用 `git merge --abort`。

## 依赖与发行边界

优先使用目标上游配套的 SDK、BOM 和构建约束，不将每个依赖分别升级到 latest 后视为兼容。安全补丁单独评估和验证。

已抓取、已合并、已测试和已发行是不同状态。基线文件记录源码来源，测试证据归对应提交的 PR/CI，发行结果归固定版本的 Release。

同步不自动修改 [Beacon 产品版本](version.properties)，也不把上游版本号当作 Beacon 发行号。保留根目录上游 Changelog；合并时核对 `javaagent/build.gradle.kts` 对 [Beacon 打包配置](agent.gradle.kts)的加载以及 CI 的 Beacon 制品上传路径。

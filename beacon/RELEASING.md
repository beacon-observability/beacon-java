# Beacon Java 发行流程

Beacon 使用独立产品版本和制品身份，[打包配置](agent.gradle.kts)由 `:javaagent` 加载。继承的官方及旧 Guance 发布任务已通过仓库条件限制，不能作为 Beacon 发行入口；具体见 [CI 说明](CI.md)。当前采用下述受控构建与人工发布流程，不依赖尚未配置的自动发布任务。

## 版本与范围

- Beacon Java 使用独立语义版本和 `beacon-vX.Y.Z` 标签，不复用旧 `v*` 标签。
- [version.properties](version.properties) 是产品版本的唯一配置源。当前 `0.1.0-SNAPSHOT` 是开发版本；正式版使用 `X.Y.Z`，公开候选版使用 `X.Y.Z-rc.N`。不发布 SNAPSHOT 为正式 Release，不通过临时命令行覆盖发行版本。
- 产品版本与[上游基线](upstream.lock.json)分别记录，不全局替换上游构建版本，也不修改应用的 `service.version`。
- 完整安装包为 `beacon-javaagent-<Beacon版本>.jar`；`base`、`dontuse` 等辅助产物不作为 Beacon 安装包发布。不使用继承的 Maven/Sonatype 发布任务发布 Beacon 产品。
- Manifest 的 `Implementation-Title` / `Implementation-Version` / `Implementation-Vendor` 标识 Beacon 产品；`Beacon-Upstream-Tag` / `Beacon-Upstream-Commit` 标识官方基线；`Beacon-Instrumentation-Version` 保留当前继承的模块构建版本。内嵌 `META-INF/beacon/` 保存版本与来源文件。
- 上游模块坐标、Java 包名和 instrumentation scope 不批量重命名。完整 JAR 的 `java -jar` 版本输出及 AgentVersion 从 Manifest 读取，因此使用 Beacon 产品版本；模块构建版本另读 `Beacon-Instrumentation-Version`。现有启动日志前缀及默认 `telemetry.distro.name` 仍由继承的运行时代码提供，不将文件命名调整描述成所有运行时标识均已品牌化。
- 每版明确实际验证的功能和支持范围。现有 Profiling 为继承的实验性实现；Extension 化单独实施，不作为首次提交源码的前置条件。
- 来源、许可证、必要第三方声明、制品摘要和已知限制随发行提供。签名、制品托管及 SBOM 生成方式在发布实现中确定。

## 发布顺序

1. 在发行 PR 中更新 `version.properties`，将 [Changelog](CHANGELOG.md) 的已完成条目归入对应版本，明确配置变化、发布范围与说明；合并后固定最终源码提交。上游 Changelog 不混入 Beacon 条目。
2. 从该提交、固定依赖和构建环境生成候选制品，记录 SHA-256 与构建来源。
3. 对该候选制品完成适用的模块、运行环境、自有增强、接收端、性能及回退验证。运行 [Beacon CI 的手动扩展验证](CI.md#重型验证与测试镜像)，并按实际支持范围补充 Windows/OpenJ9/性能等专项测试；扩展 CI 不替代候选制品验收。测试证据绑定到同一提交及制品摘要。
4. 审批后在已验证提交创建不可变的发行标签，发布已经验证的同一份制品；不在这一步修改依赖或重新构建替代品。
5. 如产品版本、Manifest 或任意制品内容变化，重新构建并验证。公开 RC 与正式版内容不同，不能直接重命名当作同一制品。
6. 将用户文档和支持范围关联到该版本。首次发行或入口、支持状态变化时更新 [Beacon 产品入口](https://github.com/beacon-observability/beacon)，不要求每个补丁版本跨仓登记。

本流程尚未绑定具体 GitHub Environment 或审批人；管理员确认后配置，不能仅凭文档认为审批已经生效。

## 候选制品构建

在干净的发行提交、JDK 21 环境下，从仓库根目录执行：

```bash
./gradlew :javaagent:assemble :javaagent:verifyBeaconAgent
```

输出位于 `javaagent/build/libs/`，按已提交的产品版本选取唯一的完整 Agent；不要用包含旧产物的通配符发布。`verifyBeaconAgent` 检查文件名、Manifest 和来源文件，不代替功能、兼容性或性能测试。SHA-256、源码提交及验证结果随候选制品保存。

审批后只推送该版本的 `beacon-vX.Y.Z` 标签，并在同名 Release 上传已经验证的同一 JAR、SHA-256 和必要声明；不要使用 `git push --tags`，不要重新构建后替换候选制品。下一开发版本在另一个提交中设置，不能混进当前发行标签。

## 回退与重试

同版本重试只允许发布相同内容。标签或制品与预期不一致时停止，不覆盖已有资产。问题版本保留追溯记录，回退到上一固定制品及对应配置。

## 构建和首次上线

构建入口见[贡献指南](../CONTRIBUTING.md)，首次 GitHub 上线与待确认项目见 [CI 检查](CI.md)。普通 assemble 成功不代表完成发行验收。

# Beacon Java Changelog

这里只记录 Beacon 产品变化。根目录 [CHANGELOG.md](../CHANGELOG.md)保留上游日志；OTel 标签和完整提交由[基线文件](upstream.lock.json)记录。

## Unreleased

## Version 1.0.0 (2026-09-28)

这是 Beacon Java 的首个公开正式版本。实际支持范围以绑定到制品摘要的验收记录为准。

### 能力移除

- 暂时移除 Taobao HSF 的 Javaagent 和 library 模块及 `hsf-sdk` 依赖，解除构建对开发机本地制品的依赖。当前 Agent 不再提供 HSF 自动插桩；原 `otel.instrumentation.hsf.enabled`、`otel.instrumentation.hsf-client.enabled` 开关无法恢复此能力。依赖 HSF 链路采集的使用者需在恢复支持并完成验证后再迁移。历史源码保留在 Git 历史中。

### 上游同步

- 合入官方 OTel Java Instrumentation [v2.31.1](https://github.com/open-telemetry/opentelemetry-java-instrumentation/releases/tag/v2.31.1)，固定提交 `8ad06a082e051f366f19c16ad95a7b68edf30afd`；采用其配套 SDK 1.65.0、依赖约束及 Gradle Wrapper。
- 保留 JDBC 旧配置兼容、Profiling、Spring AI、Alibaba Agent 等下游实现，以及 Beacon 打包与工作流隔离；HSF 暂时移除，见上述说明。本次 Beacon 产品版本为 `1.0.0`，是首个公开正式版。
- 上游 2.31.x 含非稳定 API 变更及配置弃用，升级时查看根目录[上游 Changelog](../CHANGELOG.md)；2.31.1 修复 Spring Boot autoconfigure/starter 的稳定语义约定 API 编译依赖。
- 修正 Profiling 元数据的 YAML 描述语法和默认值表示，补充文件导出路径的实际默认值；不改变运行时配置或行为。

### 工程与发行

- 源码仓库迁移至 `beacon-observability/beacon-java`，同步更新 Beacon CI 的仓库隔离条件、项目入口链接和产品厂商标识。
- 新增 Beacon 专用 CI 入口，普通 PR 缩减 JDK 矩阵、保留全部测试分片与两种 Indy 模式；共享核心及上游基线变化自动扩大验证。重型兼容性测试提供手动入口，上游 PR 镜像构建不再在 Beacon 自动执行；保留独立安全检查，新增成品 Agent 的 HTTP/TraceContext/OTLP Trace 导出烟测。
- 产品主线使用 `main`，保留完整上游历史和既有下游增强。
- 使用独立产品版本，首个公开正式版为 `1.0.0`。
- 完整 Agent 命名为 `beacon-javaagent-<Beacon版本>.jar`，Manifest 记录 Beacon 版本、模块构建版本及上游标签和提交，制品内嵌来源记录。
- 隔离继承的发布和管理自动化，保留构建检查，独立维护 Beacon 同步与发行流程。
- 用本日志记录产品变化，不再维护独立的下游差异台账。

### 初始导入

- 从历史下游提交 `73a8f7edd0415f0e8651d3d1f3f295e6e6d4d1ea` 导入完整源码；采用的官方发布祖先为 OTel Java Instrumentation `v2.30.0`。
- 继承 JDBC 旧配置兼容、实验性 JFR Profiling / DataKit 导出、Spring AI、Spring AI Alibaba Agent、HSF 插桩。这些是原分支已有实现，不是迁移后新开发或已通过 Beacon 验收的能力。

### 已知限制

- Profiling 仍是继承的实验性实现，Extension 迁移尚未完成；方向见[开发说明](README.md#profiling-的扩展边界)。
- 当前启动日志前缀和默认 `telemetry.distro.name` 仍沿用继承实现，不能将 Agent 文件名与 Manifest 的 Beacon 标识理解为所有运行时标识均已完成品牌化。

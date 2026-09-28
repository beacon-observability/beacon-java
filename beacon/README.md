# Beacon Java 开发说明

本仓库维护完整 OpenTelemetry Java Instrumentation 源码与 Beacon 增强。产品总入口为 [beacon-observability/beacon](https://github.com/beacon-observability/beacon)。

## 工程布局

以下链接均相对于本文所在目录，命令则统一从仓库根目录执行。

| 位置 | 用途 |
| --- | --- |
| [instrumentation](../instrumentation/) | 原生插桩实现与测试 |
| [javaagent](../javaagent/) | Agent 组装 |
| [javaagent-tooling](../javaagent-tooling/) | 插桩工具与加载机制 |
| [beacon](./) | 产品打包配置、版本、文档、基线和工具；不是独立 Gradle 模块 |
| [工作流](../.github/workflows/) | 构建、测试和继承的自动化定义 |

## 维护入口

- [固定来源与采用基线](upstream.lock.json)：导入记录是历史事实；上游字段记录当前采用的正式发布祖先，不表示代码与官方完全一致。
- [上游同步](UPSTREAM.md)：首次配置、固定目标提交和同步步骤。
- [Beacon Changelog](CHANGELOG.md)：产品版本变化、上游升级和兼容说明；具体代码差异和测试证据归 Git/PR。
- [Beacon 自有贡献者](CONTRIBUTORS.md)：区分 Beacon 下游贡献与继承的上游作者，保留可追溯提交证据。
- [产品版本](version.properties)与[打包配置](agent.gradle.kts)：定义完整 Agent 的产品身份，不改写上游依赖版本。
- [贡献指南](../CONTRIBUTING.md)：构建、开发和测试。
- [CI 状态与上线检查](CI.md)：哪些自动化可以运行，哪些尚未适配。
- [发行流程](RELEASING.md)：版本、制品验证与回退。

开发主线为 `main`，延续已导入的既有下游增强代码，不使用其他仓库的 `main` 替换当前代码。自定义上游引用不会仅因克隆 Beacon 仓库就出现在 `refs/upstream-tags/*` 下，需要按同步指南显式配置和抓取。

保留上游包名、工程布局和许可证。必须修改原生插桩时在对应模块开发；可独立实现的能力优先采用 Extension，不为产品品牌全仓替换上游标识。

## 当前继承的自有能力

以下是源码入口，不是已经通过 Beacon 发行验收的支持承诺：

| 能力 | 入口 |
| --- | --- |
| JDBC 旧配置兼容 | [jdbc](../instrumentation/jdbc/) |
| 实验性 JFR Profiling 与 DataKit 导出 | [profiling](../instrumentation/profiling/) |
| Spring AI 模型调用 | [spring-ai-1.0](../instrumentation/spring/spring-ai-1.0/) |
| Spring AI Alibaba Agent 与工具调用 | [spring-ai-alibaba-agent-1.0](../instrumentation/spring/spring-ai-alibaba-agent-1.0/) |

HSF 插桩已暂时移除：其 SDK 依赖仅存在于开发机本地，尚无供 CI 使用的制品来源。当前 Agent 不提供 HSF 自动插桩；历史实现保留在 Git 历史中，恢复前需先解决依赖来源并完成构建与兼容性验证。

## Profiling 的扩展边界

确定的演进方向是“实现独立、默认内置交付”。后续将 JFR 采集和导出核心、OTel 生命周期适配分别迁入同仓库的 `extensions/profiling/core/` 与 `extensions/profiling/agent-extension/`；这些目录尚未创建，不作为现有构建入口。

迁移后将同一扩展嵌入完整 Beacon Agent，用户仍只需一个 `-javaagent`；确有外置使用需求时再提供独立扩展制品。初期随 Beacon 同版发行，不另设仓库或版本周期。迁移必须移除旧的内编入口，避免重复采集，并验证 SPI、依赖隔离、多版本 JAR 与所采用 OTel 版本的兼容性。现有 Profiling 代码本轮不搬迁。

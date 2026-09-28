# Beacon Java

Beacon Java 是基于完整 OpenTelemetry Java Instrumentation 源码维护的 Java 探针工程，支持增强原生插桩，并独立发行。

当前处于开发阶段，尚无 Beacon Java 正式安装包。上游 Agent 的下载包和支持声明不代表 Beacon 的发行结果。

## 开发入口

- [开发说明与工程布局](beacon/README.md)
- [源码来源与上游基线](beacon/upstream.lock.json)
- [同步 OpenTelemetry](beacon/UPSTREAM.md)
- [发行流程](beacon/RELEASING.md)
- [Beacon 版本日志](beacon/CHANGELOG.md)
- [Beacon 自有贡献者](beacon/CONTRIBUTORS.md)
- [贡献指南](CONTRIBUTING.md)
- [CI 与首次上线检查](beacon/CI.md)

开发主线为 `main`。使用 JDK 21 执行 `./gradlew :javaagent:assemble`，完整 Agent 输出为 `javaagent/build/libs/beacon-javaagent-<Beacon版本>.jar`。产品版本见 [beacon/version.properties](beacon/version.properties)，构建不等于正式发行验收。

## 产品与上游

- [Beacon 产品入口](https://github.com/beacon-observability/beacon)
- [OpenTelemetry Java Instrumentation](https://github.com/open-telemetry/opentelemetry-java-instrumentation)
- [初始导入提交](https://github.com/beacon-observability/beacon-java/commit/73a8f7edd0415f0e8651d3d1f3f295e6e6d4d1ea)

保留上游源码布局、包名、[许可证](LICENSE)及第三方声明。产品版本、上游基线和应用自身的版本分别管理。

## Beacon Contributors

<table>
  <tr>
    <td align="center">
      <a href="https://github.com/lrwh">
        <img src="https://avatars.githubusercontent.com/u/17264378?v=4" width="72" height="72" alt="lrwh 头像"><br>
        lrwh
      </a>
    </td>
    <td align="center">
      <a href="https://github.com/songlonqi-java">
        <img src="https://avatars.githubusercontent.com/u/31207055?v=4" width="72" height="72" alt="songlonqi-java 头像"><br>
        songlonqi-java
      </a>
    </td>
  </tr>
</table>

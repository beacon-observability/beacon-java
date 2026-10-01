# Beacon Java

Beacon Java is a Java agent project maintained from the complete OpenTelemetry Java Instrumentation source tree. It supports enhanced native instrumentation and is released independently.

Download the [latest stable Beacon Java release](https://github.com/beacon-observability/beacon-java/releases/latest). Upstream agent downloads and support statements do not represent Beacon release results.

## Development resources

- [Development guide and repository layout](beacon/README.md)
- [Source provenance and upstream baseline](beacon/upstream.lock.json)
- [Synchronizing OpenTelemetry](beacon/UPSTREAM.md)
- [Release process](beacon/RELEASING.md)
- [Beacon changelog](beacon/CHANGELOG.md)
- [Beacon contributors](beacon/CONTRIBUTORS.md)
- [Contributing guide](CONTRIBUTING.md)
- [CI and initial launch checklist](beacon/CI.md)
- [Beacon Security for Java](extensions/security/README.md)

The development branch is `main`. With JDK 21, run `./gradlew :javaagent:assemble`. The complete agent is written to `javaagent/build/libs/beacon-javaagent-<Beacon-version>.jar`. See [beacon/version.properties](beacon/version.properties) for the product version. A successful build alone does not constitute release acceptance.

## Product and upstream

- [Beacon product repository](https://github.com/beacon-observability/beacon)
- [OpenTelemetry Java Instrumentation](https://github.com/open-telemetry/opentelemetry-java-instrumentation)
- [Initial import commit](https://github.com/beacon-observability/beacon-java/commit/73a8f7edd0415f0e8651d3d1f3f295e6e6d4d1ea)

The upstream source layout, package names, [license](LICENSE), and third-party notices are retained. The product version, upstream baseline, and instrumented application's own version are managed independently.

## Beacon Contributors

<table>
  <tr>
    <td align="center">
      <a href="https://github.com/lrwh">
        <img src="https://avatars.githubusercontent.com/u/17264378?v=4" width="72" height="72" alt="lrwh avatar"><br>
        lrwh
      </a>
    </td>
    <td align="center">
      <a href="https://github.com/songlonqi-java">
        <img src="https://avatars.githubusercontent.com/u/31207055?v=4" width="72" height="72" alt="songlonqi-java avatar"><br>
        songlonqi-java
      </a>
    </td>
  </tr>
</table>

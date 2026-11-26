# HTTP response trace ID

Response trace ID injection is opt-in and requires no application changes.

| System property | Default |
| --- | --- |
| `otel.instrumentation.common.http.server.response-trace-id.enabled` | `false` |
| `otel.instrumentation.common.http.server.response-trace-id.header-name` | `btrace-id` |

Environment variables are
`OTEL_INSTRUMENTATION_COMMON_HTTP_SERVER_RESPONSE_TRACE_ID_ENABLED` and
`OTEL_INSTRUMENTATION_COMMON_HTTP_SERVER_RESPONSE_TRACE_ID_HEADER_NAME`.

For declarative configuration:

```yaml
instrumentation/development:
  java:
    common:
      http:
        server:
          response_trace_id:
            enabled: true
            header_name: btrace-id
```

The value is the request SERVER span's valid 32-character lowercase hexadecimal
trace ID, including leading zeroes. Valid non-recording and unsampled spans are
included. Invalid contexts produce no header. The feature does not enable tracing
when server instrumentation is disabled.

Injection runs before response commit. If any header with the configured name
already exists, compared without case sensitivity, all application values are
preserved and no value is added. Application headers set during request processing
take precedence. Tomcat response resets are handled at final commit; async
completion and error responses use the saved request context rather than the
committing thread's current context. Status and body are not modified.

Header names must be nonempty ASCII HTTP tokens. Names controlling framing,
connection, routing, or representation are rejected: `Content-Length`,
`Transfer-Encoding`, `Connection`, `Trailer`, `Upgrade`, `Keep-Alive`, `TE`,
`Host`, `Content-Type`, `Content-Encoding`, `Content-Range`, `Location`, and
`Set-Cookie`. An invalid name disables injection and logs one warning during
provider initialization. Use a dedicated correlation header such as `btrace-id`.

## Integration scope and verification

Implemented paths are Tomcat's Coyote commit action (javax and Jakarta Servlet)
and Netty 4.1 HTTP/1 response writes. Other SPI integrations, including generic
Servlet containers, Jetty, Netty 3.8/4.0, HTTP/2, and protocol upgrades, are outside
this feature's supported scope. Legacy customizers retain their existing callback
behavior, including callbacks for Netty interim response headers. Interim responses
do not consume the final response's request context or finish its span.
Legacy mutators do not inject through the new conditional operation.

The packaged-agent regression fixture targets Tomcat **9.0.111**, Tomcat
**10.1.48**, and Netty **4.1.0.Final**. These are verification targets, not a claim
that checks have passed. Executor results must confirm support before release.

From the repository root, after assembling the complete agent, run with JDK 25
and Node.js 18 or later (Maven Central access is required for fixture dependencies):

```sh
./gradlew :instrumentation:netty:netty-4.1:library:test :javaagent-tooling:test :instrumentation:tomcat:tomcat-7.0:javaagent:test :instrumentation:tomcat:tomcat-10.0:javaagent:test :instrumentation:netty:netty-4.1:javaagent:test :javaagent:assemble
node beacon/scripts/response-trace-id-smoke.cjs javaagent/build/libs/beacon-javaagent-<Beacon-version>.jar
node beacon/scripts/agent-smoke.cjs javaagent/build/libs/beacon-javaagent-<Beacon-version>.jar
```

Replace the version with `beacon/version.properties`. The standalone fixture
launches fresh JVMs with the complete agent, no test extension/provider, and
checks unconfigured-default and explicitly disabled behavior, enabled/default/custom/
invalid names, unsampled parents, application multi-value headers, concurrent and
persistent requests, normal/error/async responses, Servlet reset, and Netty split/
interim responses. Unit tests separately check invalid context, legacy-mutator
behavior, and existing callbacks for full and split 100/103 responses.

Run repository formatting and static checks as described in
[the style guide](../docs/contributing/style-guide.md). Existing project validation
settings are unchanged. The response trace ID smoke command above must be run
explicitly; it is not yet wired into the protected CI workflow.

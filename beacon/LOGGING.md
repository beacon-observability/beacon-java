# Automatic text log correlation

Beacon can add missing correlation fields to existing text patterns without editing the application's logging configuration. Enable it at JVM startup:

```sh
java -javaagent:beacon-javaagent.jar \
  -Dotel.service.name=checkout \
  -Dotel.instrumentation.common.logging.experimental.pattern-injection.enabled=true \
  -jar app.jar
```

The equivalent environment variable is `OTEL_INSTRUMENTATION_COMMON_LOGGING_EXPERIMENTAL_PATTERN_INJECTION_ENABLED=true`. The default is `false`.

Supported layouts are Logback classic 1.0+, Log4j 1.2 PatternLayout, and Log4j2 2.7+ PatternLayout. The corresponding MDC/context-data instrumentation must remain enabled. JSON layouts and Log4j2 PatternSelector branches are excluded.

For example, `%d{yyyy-MM-dd HH:mm:ss} %-5p %m%n` becomes:

```text
%d{yyyy-MM-dd HH:mm:ss} service.name=%X{service.name} trace_id=%X{trace_id} span_id=%X{span_id} %-5p %m%n
```

Missing fields are inserted after the first complete field, preserving date formatting options and presentation wrappers. Existing MDC converters are reused and repeated initialization does not duplicate fields. An all-MDC converter in Logback, Log4j2, or later Log4j 1 releases already renders the fields and needs no additions. Early Log4j 1 releases require single-key `%X{key}` converters; Beacon detects this distinction at initialization.

The trace and span keys follow `otel.instrumentation.common.logging.trace-id-key` and `otel.instrumentation.common.logging.span-id-key`, including their supported legacy aliases. Service uses `service.name` from the configured OpenTelemetry resource, and this opt-in automatically makes it available in MDC. Application-provided values take precedence. Outside a valid span the service is still present and missing trace/span values render empty; Beacon never generates IDs just for a log line.

Patterns are parsed at layout initialization, not for each log event. Disabling the feature leaves application patterns unchanged. This setting does not configure log export or introduce Datadog `dd.*` configuration aliases.

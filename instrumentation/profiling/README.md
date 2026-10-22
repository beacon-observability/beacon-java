# Settings for the Profiling instrumentation

This instrumentation is experimental and currently targets Java 11+ JVMs with JFR available.

The first implementation focuses on:

- starting a continuous JFR recording
- taking periodic snapshots
- exporting snapshots through a pluggable adapter

The `datakit` exporter uploads JFR snapshots to a Datakit profile receiver using
`multipart/form-data`. The `file` exporter exists for validation and debugging.

| System property                                        | Environment variable                              | Type    | Default | Description                                                           |
| ------------------------------------------------------ | ------------------------------------------------- | ------- | ------- | --------------------------------------------------------------------- |
| `otel.profiling.enabled`                               | `OTEL_PROFILING_ENABLED`                          | Boolean | `false` | Enables Java profiling.                                               |
| `otel.profiling.interval`                              | `OTEL_PROFILING_INTERVAL`                         | String  | `1m`    | Interval between profiling snapshots.                                 |
| `otel.profiling.startup-delay`                         | `OTEL_PROFILING_STARTUP_DELAY`                    | String  | `0s`    | Delay before profiling starts.                                        |
| `otel.profiling.max-age`                               | `OTEL_PROFILING_MAX_AGE`                          | String  | `5m`    | Maximum retention window for the active JFR recording.                |
| `otel.profiling.stack-depth`                           | `OTEL_PROFILING_STACK_DEPTH`                      | Integer | `64`    | Unsupported per-recording option; explicit configuration emits a warning. Use the JVM JFR option described below. |
| `otel.profiling.max-size`                              | `OTEL_PROFILING_MAX_SIZE`                         | Integer | `0`     | Max JFR recording size in bytes. `0` leaves the JFR default.          |
| `otel.profiling.temp-dir`                              | `OTEL_PROFILING_TEMP_DIR`                         | String  |         | Unsupported per-recording option; explicit configuration emits a warning. Use the JVM JFR repository option described below. |
| `otel.profiling.memory.enabled`                        | `OTEL_PROFILING_MEMORY_ENABLED`                   | Boolean | `false` | Enables a memory-focused JFR overlay on top of the default profile.   |
| `otel.profiling.memory.allocation-sampling`            | `OTEL_PROFILING_MEMORY_ALLOCATION_SAMPLING`       | Boolean |         | Overrides allocation sampling events (`ObjectAllocation*`).           |
| `otel.profiling.memory.old-object-sampling`            | `OTEL_PROFILING_MEMORY_OLD_OBJECT_SAMPLING`       | Boolean |         | Overrides `OldObjectSample`.                                          |
| `otel.profiling.exporter`                              | `OTEL_PROFILING_EXPORTER`                         | String  | `none`  | Profiling exporter implementation. Supported values are `none,file,datakit`. |
| `otel.profiling.endpoint`                              | `OTEL_PROFILING_ENDPOINT`                         | String  | `http://localhost:9529/profiling/v1/input` | Datakit profile receiver endpoint. |
| `otel.profiling.datakit.timeout`                       | `OTEL_PROFILING_DATAKIT_TIMEOUT`                  | String  | `10s`   | Timeout for Datakit profile uploads.                                  |
| `otel.profiling.experimental.file-export.path`         | `OTEL_PROFILING_EXPERIMENTAL_FILE_EXPORT_PATH`    | String  |         | Output directory used by the experimental `file` exporter.            |

Legacy `otel.instrumentation.profiling.*` keys are still accepted as compatibility aliases, but
new configuration should use `otel.profiling.*`.

JFR stack depth and its repository directory are JVM-wide settings. Configure them at JVM startup
with `-XX:FlightRecorderOptions=stackdepth=128,repository=/path/to/jfr`. They affect every recording
in the process; this instrumentation does not change these global settings. The experimental
`file-export.path` setting controls exported files, separately from the JFR repository.

Profiling configuration or startup failures are logged and isolated from the remaining agent
listeners. Only settings for the selected exporter are parsed. Recording initialization runs on a
daemon worker even when startup delay is zero.

On close, the worker finishes an in-flight export and exports the remaining recording interval
before releasing the recording. The caller waits at most 10 seconds. If that deadline is exceeded,
a warning reports the pending export; the daemon worker retains resource ownership and can finish
later if the process is still running. JVM exit does not guarantee delivery beyond this deadline.
Empty JFR intervals produce no file or HTTP upload. An export failure does not advance the snapshot
cursor; a later attempt can include the interval while JFR retention still contains it.

For Datakit endpoint, the legacy environment variable `OTEL_PROFILING_DATAKIT_ENDPOINT` is also
accepted as a compatibility alias. The legacy property `otel.profiling.datakit.endpoint` is also
accepted.

Example for Datakit:

```bash
java \
  -javaagent:path/to/opentelemetry-javaagent.jar \
  -Dotel.profiling.enabled=true \
  -Dotel.profiling.exporter=datakit \
  -Dotel.profiling.endpoint=http://localhost:9529/profiling/v1/input \
  -Dotel.service.name=checkout \
  -Dotel.service.version=1.2.3 \
  -Dotel.resource.attributes=deployment.environment.name=prod \
  -jar app.jar
```

Environment variable example:

```bash
export OTEL_PROFILING_ENABLED=true
export OTEL_PROFILING_EXPORTER=datakit
export OTEL_PROFILING_ENDPOINT=http://localhost:9529/profiling/v1/input
export OTEL_PROFILING_MEMORY_ENABLED=true
export OTEL_PROFILING_MAX_AGE=1m
```

The Datakit exporter sends:

- `main` as `main.jfr`
- `event` as `event.json`

The generated `event.json` includes `tags_profiler`, `start`, `end`, `family=java`,
`language=java`, and `format=jfr`.

When `otel.profiling.memory.enabled=true`, the profiler turns on a memory-oriented
JFR overlay on top of the built-in `profile` template. You can also override allocation
sampling and old-object sampling independently.

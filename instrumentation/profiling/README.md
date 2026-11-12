# Settings for the Profiling instrumentation

This instrumentation is experimental and currently targets Java 11+ JVMs with JFR available.

The first implementation focuses on:

- starting a continuous JFR recording
- taking periodic snapshots
- exporting snapshots through a pluggable adapter

The `otlp` exporter converts execution and native-method samples, allocation samples,
and old-object samples from JFR into OTLP Profiles. It supports HTTP/protobuf and gRPC.
The `file` exporter writes original JFR snapshots, including events not converted to OTLP.
These source changes require a new Beacon release.

| System property                                        | Environment variable                              | Type    | Default | Description                                                           |
| ------------------------------------------------------ | ------------------------------------------------- | ------- | ------- | --------------------------------------------------------------------- |
| `otel.profiling.enabled`                               | `OTEL_PROFILING_ENABLED`                          | Boolean | `false` | Enables Java profiling.                                               |
| `otel.profiling.interval`                              | `OTEL_PROFILING_INTERVAL`                         | String  | `1m`    | Interval between profiling snapshots.                                 |
| `otel.profiling.startup-delay`                         | `OTEL_PROFILING_STARTUP_DELAY`                    | String  | `0s`    | Delay before profiling starts.                                        |
| `otel.profiling.max-age`                               | `OTEL_PROFILING_MAX_AGE`                          | String  | `5m`    | Maximum retention window for the active JFR recording.                |
| `otel.profiling.stack-depth`                           | `OTEL_PROFILING_STACK_DEPTH`                      | Integer | `64`    | Unsupported per-recording option; explicit configuration emits a warning. Use the JVM JFR option described below. |
| `otel.profiling.max-size`                              | `OTEL_PROFILING_MAX_SIZE`                         | Integer | `0`     | Max JFR recording size in bytes. `0` leaves the JFR default.          |
| `otel.profiling.temp-dir`                              | `OTEL_PROFILING_TEMP_DIR`                         | String  | JVM temp directory | Directory for detached final snapshots, removed after export. This does not change the JFR repository. |
| `otel.profiling.memory.enabled`                        | `OTEL_PROFILING_MEMORY_ENABLED`                   | Boolean | `false` | Enables a memory-focused JFR overlay on top of the default profile.   |
| `otel.profiling.memory.allocation-sampling`            | `OTEL_PROFILING_MEMORY_ALLOCATION_SAMPLING`       | Boolean |         | Overrides allocation sampling events (`ObjectAllocation*`).           |
| `otel.profiling.memory.old-object-sampling`            | `OTEL_PROFILING_MEMORY_OLD_OBJECT_SAMPLING`       | Boolean |         | Overrides `OldObjectSample`.                                          |
| `otel.profiling.exporter` | `OTEL_PROFILING_EXPORTER` | String | `otlp` | `otlp` or `file`. Disable profiling using `OTEL_PROFILING_ENABLED=false`. |
| `otel.exporter.otlp.profiles.protocol` | `OTEL_EXPORTER_OTLP_PROFILES_PROTOCOL` | String | Shared protocol, then `http/protobuf` | `http/protobuf` or `grpc`; OTLP only. |
| `otel.exporter.otlp.profiles.endpoint` | `OTEL_EXPORTER_OTLP_PROFILES_ENDPOINT` | String | Protocol-dependent | Exact signal endpoint; OTLP only. |
| `otel.exporter.otlp.profiles.timeout` | `OTEL_EXPORTER_OTLP_PROFILES_TIMEOUT` | Duration | Shared timeout, then `10s` | OTLP only. |
| `otel.exporter.otlp.profiles.headers` | `OTEL_EXPORTER_OTLP_PROFILES_HEADERS` | String | Shared headers | Percent-encoded `key=value` pairs; OTLP only. |
| `otel.profiling.file.path` | `OTEL_PROFILING_FILE_PATH` | String | `${java.io.tmpdir}/otel-profiles` | Local output directory; file only. |

JFR stack depth and its repository directory are JVM-wide settings. Configure them at JVM startup
with `-XX:FlightRecorderOptions=stackdepth=128,repository=/path/to/jfr`. They affect every recording
in the process; this instrumentation does not change these global settings. The `file.path` setting controls exported files, separately from the JFR repository.

Profiling configuration or startup failures are logged and isolated from the remaining agent
listeners. Only settings for the selected exporter are parsed. Recording initialization runs on a
daemon worker even when startup delay is zero.

On close, the worker finishes an in-flight export and exports the remaining recording interval
before releasing the recording. The caller waits at most 10 seconds. If that deadline is exceeded,
a warning reports the pending export; the daemon worker retains resource ownership and can finish
later if the process is still running. JVM exit does not guarantee delivery beyond this deadline.
Empty JFR intervals produce no file or HTTP upload. An export failure does not advance the snapshot
cursor; a later attempt can include the interval while JFR retention still contains it.

The JDK's own shutdown hook can stop JFR and remove its repository concurrently with application
hooks. Final snapshots are detached to temporary files before that cleanup can invalidate their
streams. The native-stop listener only preserves data; the serialized worker owns network export.
JFR chunks before the current successful-export cursor are excluded from a detached snapshot.
If JDK cleanup wins a stop/read race, the most recent detached snapshot supplies its actual end
timestamp. Files are removed after export or session cleanup; abrupt process termination can leave
temporary files behind. `temp-dir` controls these files, separately from the JVM JFR repository.

Example for OTLP/HTTP:

```bash
export OTEL_PROFILING_ENABLED=true
export OTEL_PROFILING_EXPORTER=otlp
export OTEL_EXPORTER_OTLP_PROFILES_PROTOCOL=http/protobuf
export OTEL_EXPORTER_OTLP_PROFILES_ENDPOINT=http://localhost:4318/v1development/profiles
java -javaagent:beacon-javaagent.jar -jar app.jar
```

For gRPC use `OTEL_EXPORTER_OTLP_PROFILES_PROTOCOL=grpc` and
`OTEL_EXPORTER_OTLP_PROFILES_ENDPOINT=http://localhost:4317`.
The receiver must support the development OTLP Profiles schema; an OTLP traces
endpoint alone is insufficient. `https://` enables TLS.

When the signal endpoint is unset, `OTEL_EXPORTER_OTLP_ENDPOINT` is used:
HTTP appends `/v1development/profiles`; gRPC uses the endpoint unchanged.

For local output:

```bash
export OTEL_PROFILING_ENABLED=true
export OTEL_PROFILING_EXPORTER=file
export OTEL_PROFILING_FILE_PATH=./profiles
java -javaagent:beacon-javaagent.jar -jar app.jar
```

File export ignores OTLP endpoint, protocol, headers and timeout configuration.
The old multipart exporter, endpoint settings and exporter identifier are removed.

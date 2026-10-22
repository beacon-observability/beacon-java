# Java review regression checks

The review fixes cover Security collection and export, Spring AI / Alibaba instrumentation,
Profiling lifecycle, and JDBC compatibility configuration. Build with JDK 25. Run the following
probes against the complete packaged agent, in addition to the affected Gradle test tasks.

## Complete agent probes

```sh
node beacon/scripts/agent-smoke.cjs javaagent/build/libs/beacon-javaagent-1.3.0.jar
node beacon/scripts/security-smoke.cjs javaagent/build/libs/beacon-javaagent-1.3.0.jar \
  beacon/testing/security-smoke-fixture/build/libs/beacon-security-smoke-fixture.jar
node beacon/scripts/profiling-shutdown-smoke.cjs javaagent/build/libs/beacon-javaagent-1.3.0.jar
```

Set `JAVA_HOME` to the runtime under test. Security uses the existing Boot 2 fixture and supports
Java 8/11/17/21. The profiling probe requires Java 11+ on POSIX HotSpot: it compiles a custom JFR
marker, waits for an earlier periodic file export, commits the final marker and exits the JVM.
A fresh JVM reads the exported files and verifies the marker. Each invocation repeats this three
times and checks that detached staging files were deleted.

The slow-receiver case pauses the HTTP request body, records approximately 8 MB of JFR events,
and sends SIGQUIT to capture a thread dump. It requires an actual socket-write stack in the
Datakit exporter, a shutdown-deadline warning, and exit within 13 seconds of the application's
exit request despite a 60-second network timeout. Data beyond the 10-second shutdown wait remains
best effort; this check does not promise delivery to the unavailable receiver.

## Allocation and latency probe

```sh
node beacon/scripts/security-hotpath-benchmark.cjs /path/to/baseline-agent.jar \
  javaagent/build/libs/beacon-javaagent-1.3.0.jar
```

This Java 11+ probe compares Security disabled, the baseline enabled, and the fixed agent enabled.
It repeats 100,000 StringBuilder operations with integer values outside the boxing cache. It
measures allocation and loop time without an active request and inside instrumented HTTP requests.
Warm-up precedes ten measured HTTP requests; health counters verify that the enabled cases really
entered collection. The output includes every sample and medians. It measures a narrow hot path,
not application throughput or production request P99.

## Ledger snapshot contention probe

`fixtures/SecurityLedgerBenchmark.java` uses the real extension classes with no instrumentation
agent. Extract `extensions/beacon-security-extension.jar` from each complete agent JAR, compile the
probe with that extension on the classpath, and run it with both the extension and its matching
complete agent JAR on the classpath (the latter supplies bootstrap logging classes).

```sh
javac --release 11 -cp /path/to/security-extension.jar -d /tmp/ledger-probe \
  beacon/scripts/fixtures/SecurityLedgerBenchmark.java
java -cp /tmp/ledger-probe:/path/to/security-extension.jar:/path/to/agent.jar \
  SecurityLedgerBenchmark
```

The fixture loads 4,096 findings, disables local output, and runs four request workers against
100 forced snapshots separated by 10 ms. Request samples start while a snapshot is active;
output reports their begin/end P50, P99 and maximum duration plus snapshot P50. Repeat both
versions in alternating order. This deliberately stresses contention above the normal one-second
snapshot cadence. Scheduling and GC affect individual maxima; retain all runs and state the
workload when reporting results.

Pure accumulator unit tests live in `spring-ai-1.0:javaagent-unit-tests`, separate from real-agent
integration tests. Indy instrumentation isolates its helper classes from the application loader,
so direct helper references belong in that module.

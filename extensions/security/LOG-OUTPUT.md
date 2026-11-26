# Security log output

The development Agent implements `beacon-security-log-record-v1`, pinned to the
immutable revision in [`beacon/security-spec.properties`](../../beacon/security-spec.properties).
Schema v2 and fingerprint v1 are unchanged logical contracts. The bound Body uses
[a dedicated schema](schema-log-body-v1.json); `schema-v2.json` continues to describe
full logical events and historical complete v2 JSON.

## Wire placement

| Information | Location |
| --- | --- |
| Event time | Native OTLP LogRecord `time_unix_nano`, Unix epoch nanoseconds. |
| Finding occurrence ID | LogRecord `attributes.event_id`, preserving the logical occurrence value. |
| Inventory event ID | LogRecord `attributes.event_id`, the existing deterministic round/part ID. |
| Event source | Existing Body `source` and LogRecord `attributes.source`. |
| Other event data | One compact, single-line JSON object directly in string Body. |

Body omits `observed_at` and `occurrence_id`, and does not add `event_id`, a SIEM
envelope, or a `message` wrapper. All other fields and nested evidence retain their
existing positions and meaning. Body `schema_version=2` remains at the top level.
`instance_id` identifies a process, not an occurrence; it is not replaced with the
per-event ID. Resource and Scope metadata, INFO severity, native event name,
`event.name`, and native invocation trace/span association remain intact.

Timestamp conversion uses exact integer nanoseconds from the logical event's
`observed_at`, with a positive signed-int64 receiver range. Invalid/zero/overflowing
times are rejected and counted as export loss. Queueing and retries do not replace
the timestamp with export time. A source with millisecond precision is multiplied
by 1000000, without inventing additional precision. Native OTel observation time
remains separate from the event time.

Inventory IDs are computed from the logical source, event name, process ID,
original observation timestamp string, and part index before Body compaction,
using the pinned specification's SHA-256 algorithm. Receivers retain the supplied
ID; they do not recompute it from reformatted native time. Assemble inventory
using Body `instance_id`, native event time, and Body `part_index/part_count`.
All parts of a collection have identical event time. Body `started_at` and
`uptime_ms` retain process-start and uptime semantics.

## Limits and local evidence

Per-record byte/rate limits and inventory splitting use final UTF-8 Body bytes
after the two field moves, with no SIEM escaping overhead. Actual OTel request
limits also include transport metadata. Existing evidence truncation is declared;
a finding still over the Body limit is dropped with a local loss counter. Inventory
splitting retains every dependency exactly once.

Optional evidence JSONL is a file-only logical record:

```json
{"time_unix_nano":"1790899200000000000","body":"{\"schema_version\":2,...}","attributes":{"event_id":"ev-...","source":"beacon_security","event.name":"beacon.security.finding"}}
```

This illustrative Body is abbreviated. Actual lines retain the exact OTLP Body
string, native event time as a decimal string, and event attributes. A single LF
separates file records. Rotation budgets count actual diagnostic file bytes,
including JSON escaping. This wrapper is never sent as an OTLP Body. Body-only
archives cannot recover the moved timestamp or occurrence ID.

## Receiver migration

Compared with 1.5.0, stop parsing the SIEM `message` wrapper. Decode Body once,
read native event time and `attributes.event_id`, and retain existing paths for
all remaining fields. Compared with complete v2 JSON from earlier versions,
only Body `observed_at` and `occurrence_id` have moved. Consumers of the evidence
file must read its logical record metadata and decode its `body` string.
Historical records are not rewritten. The wire profile in Manifest/embedded
provenance identifies this binding independently of Body `schema_version`.

The fifteen-field SIEM projection is optional downstream processing, not an Agent
export mode. Tenant, authenticated actor, client IP, assessed severity, and execution
outcome are not invented as new producer fields by this correction.

## Verification

Six [pinned logical-record fixtures](src/test/resources/log-record-v1/) cover
findings, compact occurrences, full/multipart/empty inventory. Unit tests check
metadata moves, exact timestamps and IDs, nested/escaped evidence, final Body
limits, and file/OTLP metadata parity. The packaged-agent
[`security-smoke.cjs`](../../beacon/scripts/security-smoke.cjs) decodes real OTLP
HTTP/protobuf, checks native event metadata and unwrapped Body, and compares them
to diagnostic JSONL. This local receiver does not certify a deployed DataKit version.

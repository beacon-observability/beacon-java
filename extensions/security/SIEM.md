# Security SIEM output

The development Agent adopts the `beacon-security-siem-v1` profile pinned in
[`beacon/security-spec.properties`](../../beacon/security-spec.properties). This change is
unreleased. Older Agents emit a v2 event directly. New OTel LogRecord string Bodies and evidence
JSONL lines contain the following fifteen required string fields, required process identity,
and available trace correlation:

| Field | Finding | Dependency inventory |
| --- | --- | --- |
| `time` | Original `observed_at`. | Original `observed_at`. |
| `event_id` | Original `occurrence_id`. | `inventory-` + deterministic SHA-256 as defined by the pinned profile. |
| `event_class` | `security_finding` | `software_inventory_info` |
| `source` | `beacon_security` | `beacon_security_sbom` |
| `service` | OTel Resource `service.name`, otherwise empty. | Same. |
| `tenant_id` | Explicit Resource `tenant.id`, otherwise `default`. | Same. |
| `actor` | Empty; no new principal collection. | Empty. |
| `ip` | Empty; no new client-address collection. | Empty. |
| `action` | Original `rule`. | `inventory_snapshot` |
| `target` | Original `finding_id`. | Original `instance_id`. |
| `target_type` | `finding` | `process` |
| `outcome` | `unknown` | `success` (local collection only). |
| `status` | `info` | `info` |
| `severity` | `informational` | `informational` |
| `message` | Complete serialized v2 finding. | Complete serialized v2 inventory part. |

Findings inside `message` expose the current invocation span as `span_id`; `server_span_id` is
not exported, and `current_span_id` is no longer an output field or schema alias. The current span is retained
even when it is the HTTP server span. Internal server-context tracking and the existing finding
fingerprint remain unchanged. Native OTel association follows the invocation span as described below.

The outer envelope also requires `instance_id` (the process UUID). It preserves available
`trace_id`, `span_id`, and `trace_flags` from the embedded event. Trace IDs and span IDs are
strings; `trace_flags` is an integer in 0..255, including zero. Missing span IDs are omitted.
Inventory does not inherit request trace context. OTel LogRecords associate with the observed
invocation span; a missing invocation span never falls back to a different request-entry span.
There is no format-selection switch or legacy-output fallback.

The [envelope JSON Schema](schema-siem-v1.json) and six pinned
[unenriched conformance fixtures](src/test/resources/siem-v1/) describe the output. Java does not
implement the optional trusted request-context enrichment in the specification's enriched vector.
No additional authentication, proxy-header, or tenant discovery hooks are introduced.

Resource identity is resolved through the existing Agent resource customizer. For example,
`OTEL_RESOURCE_ATTRIBUTES=tenant.id=customer-a` explicitly sets the application-provided tenant.
When absent, empty, or whitespace-only, `tenant_id` is `default`. A trusted receiving system can
bind its own tenant; the emitted field is not an authorization or isolation boundary. Service and
tenant Resource attributes remain associated with the OTel record.

`status` and `severity` reflect INFO logging, not an assessed vulnerability risk. Attack-evidence
`unknown` / `no_evidence` / `suspected` and its reason remain inside `message`. None proves sink
completion or exploit success; finding `outcome` is always `unknown`. The existing default
`no_evidence` export filter still applies before queue admission to both OTLP and JSONL. Setting
`BEACON_SECURITY_EXPORT_NO_EVIDENCE_ENABLED=true` restores those events. SBOM is unaffected.

## Original data and limits

For an Agent, the original message is the v2 JSON serialized at the existing export boundary,
after existing evidence sampling and declared truncation. Projection retains that string exactly,
including Unicode and JSON escape spelling. It does not substitute a summary or reserialize a
parsed copy. JSONL and OTLP receive the same envelope bytes. Local `findings.json`, `runs.json`,
`health.json`, and CycloneDX snapshots retain their diagnostic formats.

Original preservation does not recover uncollected, sampled-out, truncated, or dropped evidence.
It also does not archive the entire OTLP Resource/Scope/attribute record. Those remain in their
native transport context. Use separate transport archival if required.

Per-record and per-second budgets count the final envelope bytes, including the escaping of
`message`. Existing oversized v2 findings can remove optional evidence with explicit
`truncated=true` and a reason before serialization. If the resulting envelope cannot fit, it is
dropped with local `record_limit_exceeded` and channel-loss counters rather than silently
shortening the original message. There is no diagnostic replacement event or replay backlog.

Inventory planning includes the envelope, Resource identity, and double-escaped row sizes. Each
dependency is retained exactly once across successful parts. Changing Resource configuration
requires restarting the Agent, as with existing startup settings.

## Consumer migration

1. Validate the outer envelope with `schema-siem-v1.json`; the fifteen base fields are strings,
   process identity is required, and trace flags remain numeric. The profile
   is recorded in Manifest `Beacon-Security-Wire-Profile` and embedded `wireProfile` / `wire.profile`
   provenance, independently of embedded payload `schema_version=2` and fingerprint version 1.
2. Parse `message` as JSON for `event_name`, request, sink, attack-evidence classification,
   sampling, coverage, components, and evidence. Process/trace correlation is also available
   directly in the envelope. Historical records retain their originally pinned interpretation.
3. Deduplicate findings by tenant/source/process/occurrence; group issues by `target` (finding ID).
   The finding target is the problem, not a database URL, shell command, or file path.
4. Assemble inventory by embedded `instance_id + observed_at`, using embedded
   `part_index/part_count`. Only replace a list when all parts arrive; reject stale rounds.
   A successful empty list can clear the previous inventory. Missing updates do not prove health.
5. A DataKit pipeline must map envelope `source` to the measurement and `time` to Point time,
   retaining envelope `message` as the original payload. DataKit may otherwise choose a source
   from Resource attributes instead of the per-record source. No collector pipeline is deployed
   by this Java change.

OTel scope `io.beacon.security`, product version, INFO level, and event name / `event.name` / `source`
remain unchanged. Native SpanContext association uses the observed invocation when available.
No duplicate v2 copy is sent on the same route. See the implementation PR for unit, byte-budget, and real OTLP smoke evidence.

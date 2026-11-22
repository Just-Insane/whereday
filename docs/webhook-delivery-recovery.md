# Webhook delivery recovery

Webhook delivery remains opt-in and uses the endpoint, format and credentials configured in the app. The sender retains pending points, independently prepared request bytes and its cursor in protected, backup-excluded application storage. It binds that state to a one-way hash of the destination and current authorization, including custom headers and query credentials. The queue does not store another copy of credentials.

An automatic cursor is armed when delivery is enabled and attached to the native location store. It survives relaunch and advances only when an export is confirmed, or when the user explicitly clears waiting work. Point IDs distinguish records that share the cursor timestamp. Existing saved-point observations feed both realtime and batch modes; existing app-active events and the batch timer resume pending work. No additional scheduler or location permission is introduced.

## Prepared requests

Before a POST, the sender saves each complete serialized body and its SHA-256 digest. All chunks of a history snapshot enter the durable queue together through one directory rename before any is selected for delivery. Subsequent retries reopen those exact immutable bytes; they do not regenerate the export time or records. Operation metadata retains the attempted state, account-bound receiver identity and membership progress before the network call. Acceptance persists a settlement receipt before advancing the cursor or removing body bytes, so interruption between those steps cannot turn an acknowledged export into an unattempted draft. Existing single-request state remains readable. A point queued while delivery is in progress is preserved.

Visits-only exports are supported by JSON, CSV, Markdown, GPX, KML and GeoJSON. OwnTracks and Overland require location points and report that limit when given visits alone. JSON history is split between complete native point/visit objects into ordinary envelopes of at most 16 MiB. Each envelope preserves the original export time, all native and unknown fields, and local point/visit counts. The native source indices bind each chunk to its actual point UUIDs in local custody; no point identity or timestamp is invented in the payload. Bodies are stored separately, so the complete history selection does not need to fit in one queue-state file. An indivisible record above the limit, unsupported large format, or chunks with indistinguishable exact identities are explicitly held rather than silently clipped or collapsed. Automatic point batches still use the configured point count.

New source points are queued even while another request is awaiting a response. Each drain round prepares fresh points first, selects pending operations by their newest native source time, and visits each operation once. Historical requests receive one recovery opportunity per round; an unresolved historical receipt remains intact while independent fresh envelopes proceed. App-active events, native saved-point observations and the existing batch timer resume this work; this adds no scheduler or background execution entitlement. A new manual history action resumes an existing prepared history snapshot instead of regenerating uncertain originals.

Changing the endpoint, format or credentials does not send an older queue to the new configuration. The non-secret `X-Whereday-Export-Format` header identifies the format token explicitly, including formats that share a MIME type, and participates in the local binding. Returning to the original settings makes its saved work available again. Disabling delivery retains the queue without sending it.

## Optional receiver receipt contract

A supporting receiver can reconcile interrupted deliveries without duplicating a write. The sender first makes an authenticated GET to the configured endpoint, adding:

```
X-Whereday-Export-SHA256: <SHA-256 of the exact body>
```

A recognized response is HTTP 200 with JSON containing the matching `sha256`, an opaque account-bound `capture.export_id` of at most 512 characters, and one of these states:

```json
{
  "status": "capture_pending",
  "sha256": "<matching digest>",
  "capture": { "export_id": "<opaque account-bound identity>" },
  "retry_same_original": true
}
```

`accepted` confirms that exact original is already retained. `capture_pending` authorizes a POST only when `retry_same_original` is explicitly true. Absence alone is not permission to repeat an uncertain operation: the receiver must implement an idempotent original-byte capture and recheck its current source, account and item authority.

The sender pins the returned identity before the first POST and sends it as `X-Whereday-Export-ID`. A supporting receiver must reject a changed identity. Its successful POST response must return `status: accepted`, the matching digest and the same `capture.export_id`. An interrupted membership inventory may use HTTP 503 with `status: capture_membership_pending`, `export_id`, increasing `next_cursor`, stable `total` and `retry_same_original: true`. Its progress is saved, and every retry first checks the authenticated receipt again.

The three `X-Whereday-Export-*` headers are reserved for this protocol and cannot also be selected as a custom authentication header.

HTTP 404, 405 or 501 from the initial GET, or an ordinary HTTP 200 without the receipt protocol, permits the original POST behavior for a generic endpoint. If that POST has an uncertain result, the sender holds it: generic endpoints without a pinned receipt contract cannot automatically reconcile an unknown write. A changed account identity, mismatched digest, unavailable receipt or damaged local body also holds the request without a repeat or cursor advance. Clearing waiting points preserves an uncertain delivery; it is not silently discarded.

## Verification

Run the canonical simulator test entry point with signing enabled:

```sh
scripts/test-ios.sh -only-testing:IsoMeTests/WebhookManagerTests
```

The suite uses isolated defaults, temporary queue storage and mocked HTTP. `WebhookContinuationTests` additionally covers lossless bounded partitioning, visits-only history, every chunk surviving restart, independent fresh priority while an older account-bound receipt remains unknown, and a crash between receipt settlement and cursor advancement. It covers visits-only delivery, persistent points/cursor, a lost acknowledgement without another POST, explicit identical-body continuation, changed account or credentials, damaged bytes, disabled delivery and generic unknown results. Passing these source tests is separate from installing a signed app and observing a genuine phone export.

The app's optional iOS 27.1 arrangement/hinge layouts require their SDK symbols as well as runtime availability. App builds selecting the iPhoneOS or iPhone Simulator 27.0 SDK define `WHEREDAY_NO_DUO_SDK` and use the existing fallback layouts. The newer layouts and their runtime guards remain available with supported newer SDKs; a compiler version alone does not prove those SDK symbols exist. This compatibility condition leaves normal simulator signing and other targets unchanged.

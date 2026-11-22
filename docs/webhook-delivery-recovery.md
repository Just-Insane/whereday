# Webhook delivery recovery

Webhook delivery remains opt-in and uses the endpoint, format and credentials configured in the app. The sender now retains pending points, prepared request bytes and its cursor in protected, backup-excluded application storage. It binds that state to a one-way hash of the destination and current authorization, including custom headers and query credentials. The queue does not store another copy of credentials.

An automatic cursor is armed when delivery is enabled and attached to the native location store. It survives relaunch and advances only when an export is confirmed, or when the user explicitly clears waiting work. Point IDs distinguish records that share the cursor timestamp. Existing saved-point observations feed both realtime and batch modes; existing app-active events and the batch timer resume pending work. No additional scheduler or location permission is introduced.

## Prepared requests

Before a POST, the sender saves each complete serialized body and its SHA-256 digest in protected storage. Independent operation metadata holds that body's attempted state, pinned receiver identity, membership progress and final receipt. Bodies are not combined into one growing state file. A prepared history selection publishes all its originals through one staging-directory rename before any part becomes eligible for transmission. Interrupted staging is never submitted.

The attempted state is durable before the network call. Acceptance is durable before cursor advancement or body cleanup, so an interrupted cursor update cannot turn an accepted original back into a new upload. The existing single-request state can be reopened and migrated without changing its body or receipt. Pending points admitted while a response is outstanding are preserved.

Visits-only exports are supported by JSON, CSV, Markdown, GPX, KML and GeoJSON. OwnTracks and Overland require location points and report that limit when given visits alone. Automatic point batches use the configured point count.

An oversized native JSON history export is partitioned only between complete point and visit objects. Every resulting envelope is at most 16 MiB, retains the original `exportDate` and other top-level values, preserves every field in each selected native record, and recomputes its local point/visit counts. The native point IDs and visit revisions remain associated with the correct originals. These are ordinary JSON export envelopes using the same receipt protocol; no receiver reassembly format is needed. An already bounded export retains its exact original bytes.

An indivisible record or envelope metadata that cannot fit produces an explicit unsent error before any part of that selection is published or transmitted. Other oversized formats also remain unsent. Nothing is clipped, and the saved native source remains available. Indistinguishable bodies with different native membership are held explicitly rather than silently collapsing distinct records.

Manual refresh fetches the current saved source even if older history is unresolved. Durable native point membership and visit revisions prevent unchanged records from being re-exported under a new `exportDate`. New points, new visits and changed exported visit values create independent work. Existing originals remain byte-for-byte unchanged, with their own receipts. Confirmed membership remains local so a restart or another manual refresh does not recreate accepted operations.

Legacy JSON operations without native visit IDs retain the hashes of their original exported visits in settled metadata before body cleanup. Opaque legacy formats whose visit membership cannot be recovered explicitly hold further visit admission for review; a failed parse is never interpreted as an empty history. Independently identified location points can still proceed while that visit uncertainty is retained.

Changing the endpoint, format or credentials does not send an older queue to the new configuration. The non-secret `X-Whereday-Export-Format` header identifies the format token explicitly, including formats that share a MIME type, and participates in the local binding. Returning to the original settings makes its saved work available again. Disabling delivery retains the queue without sending it.

Each existing flush task admits fresh points before choosing its next operation, serves fresh work before history, and visits each original at most once in that round. A held or unknown operation retains its exact identity while independent siblings can proceed. Historical recovery gets one attempt per round; each continuation still requires the exact authenticated receipt. The first unresolved failure remains visible even if other work succeeds. One actual sender is active at a time, but native observations and manual source admission can persist fresh work while it awaits HTTP.

The task yields between bounded requests and continues its backlog without another location event or a new scheduler. Cancellation, changed settings or disabled delivery stops the round and retains the remainder. If iOS ends execution, the next existing app-active/location/timer event resumes saved work. Damaged custody metadata is reported as an integrity failure; it is not discarded or treated as permission to recreate a request.

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
scripts/test-ios.sh \
  -only-testing:IsoMeTests/WebhookManagerTests \
  -only-testing:IsoMeTests/WebhookContinuationTests \
  -only-testing:IsoMeTests/WebhookJSONPartitionerTests
```

The selected suite uses isolated defaults, temporary queue storage and mocked HTTP. It covers visits-only delivery, persistent points/cursor, a lost acknowledgement without another POST, explicit identical-body continuation, changed account or credentials, damaged bytes, disabled delivery, generic unknown results, all-chunk restart recovery and a receipt surviving an interrupted cursor update. Partition cases exercise exact boundaries, visits-only/mixed exports, unknown nested fields, source membership and indivisible oversize errors. Manager cases verify fresh/changed manual rows beside unknown history and a new point arriving during a history POST. Passing these source tests is separate from installing a signed app and observing a genuine phone export.

The app's optional iOS 27.1 arrangement/hinge layouts require their SDK symbols as well as runtime availability. App builds selecting the iPhoneOS or iPhone Simulator 27.0 SDK define `WHEREDAY_NO_DUO_SDK` and use the existing fallback layouts. The newer layouts and their runtime guards remain available with supported newer SDKs; a compiler version alone does not prove those SDK symbols exist. This compatibility condition leaves normal simulator signing and other targets unchanged.

## Connection probes

Test connection sends a small JSON control object with schema
`whereday.connection_probe` and `schema_version: 1`. It contains no location
point, visit, export date or source observation, regardless of the selected
export format. The same configured URL, authentication and native client identity
are used. It does not enter the export outbox, advance source membership or mark
LAST SENT as an ordinary export.

An endpoint supporting this probe acknowledges access without storing it as
location data. EA's matching receiver returns `status: connection_verified` and
`capture: false` after its normal source checks; other endpoints may reject an
unsupported probe contract. A probe result does not establish history coverage
or automatic Live delivery. Genuine source exports retain their existing format.

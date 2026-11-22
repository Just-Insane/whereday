# Webhook delivery recovery

Webhook delivery remains opt-in and uses the endpoint, format and credentials configured in the app. The sender now retains pending points, prepared request bytes and its cursor in protected, backup-excluded application storage. It binds that state to a one-way hash of the destination and current authorization, including custom headers and query credentials. The queue does not store another copy of credentials.

An automatic cursor is armed when delivery is enabled and attached to the native location store. It survives relaunch and advances only when an export is confirmed, or when the user explicitly clears waiting work. Point IDs distinguish records that share the cursor timestamp. Existing saved-point observations feed both realtime and batch modes; existing app-active events and the batch timer resume pending work. No additional scheduler or location permission is introduced.

## Prepared requests

Before a POST, the sender atomically saves the complete serialized body and its SHA-256 digest. The original `exportDate`, visits and points are retained byte-for-byte. The attempted state is saved before the network call. On acceptance, one atomic state replacement records the delivery cursor and removes the acknowledged work together. A point queued while delivery is in progress is preserved.

Visits-only exports are supported by JSON, CSV, Markdown, GPX, KML and GeoJSON. OwnTracks and Overland require location points and report that limit when given visits alone. An export larger than 16 MiB is held with an explicit error; it is never clipped. Automatic point batches use the configured point count. Manual exports still include all saved data and can exceed that limit.

Changing the endpoint, format or credentials does not send an older queue to the new configuration. The non-secret `X-Whereday-Export-Format` header identifies the format token explicitly, including formats that share a MIME type, and participates in the local binding. Returning to the original settings makes its saved work available again. Disabling delivery retains the queue without sending it.

Each existing flush task continues through its saved backlog in bounded point batches until empty, cancelled, disabled or stopped by an error. It yields between requests so native observations can add points without losing them. This continuation does not require another location event and adds no scheduler. If iOS ends execution, the next existing app-active/location/timer event resumes the retained remainder.

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

The suite uses isolated defaults, temporary queue storage and mocked HTTP. It covers visits-only delivery, persistent points/cursor, a lost acknowledgement without another POST, explicit identical-body continuation, changed account or credentials, damaged bytes, disabled delivery and generic unknown results. Passing these source tests is separate from installing a signed app and observing a genuine phone export.

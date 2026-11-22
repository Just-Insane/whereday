import CryptoKit
import Security
import XCTest
@testable import IsoMe

/// Tests for the security- and correctness-sensitive parts of WebhookManager:
/// keychain round-trip, the one-time UserDefaults → Keychain migration, and
/// the error-message sanitization that prevents API keys from leaking into
/// persisted error logs.
@MainActor
final class WebhookManagerTests: XCTestCase {

    private let testAccount = "webhook.tests.authValue"
    private let testLegacyKey = "webhook.tests.authValue"
    private var defaults: UserDefaults!
    private var defaultsSuiteName: String!
    private var outboxDirectory: URL!

    override func setUpWithError() throws {
        try super.setUpWithError()
        defaultsSuiteName = "WebhookManagerTests.\(UUID().uuidString)"
        defaults = UserDefaults(suiteName: defaultsSuiteName)!
        defaults.set(true, forKey: "webhook.enabled")
        outboxDirectory = FileManager.default.temporaryDirectory.appendingPathComponent(defaultsSuiteName)
        WebhookManager.keychainWriteString("", account: testAccount)
        UserDefaults.standard.removeObject(forKey: testLegacyKey)
        MockWebhookURLProtocol.reset()

        // Fail in setup with the real Security error, rather than misleading nil-value assertions.
        let probe: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "WebhookManagerTests.preflight",
            kSecAttrAccount as String: UUID().uuidString,
            kSecValueData as String: Data("probe".utf8),
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlock,
        ]
        let status = SecItemAdd(probe as CFDictionary, nil)
        guard status == errSecSuccess else {
            let message = status == errSecMissingEntitlement
                ? "Keychain setup failed: errSecMissingEntitlement (-34018). Run scripts/test-ios.sh with simulator signing enabled; CODE_SIGNING_ALLOWED=NO prevents Keychain access."
                : "Keychain setup failed with OSStatus \(status). Check simulator Keychain availability before diagnosing credential assertions."
            throw NSError(domain: "WebhookManagerTests.KeychainSetup", code: Int(status),
                          userInfo: [NSLocalizedDescriptionKey: message])
        }
        var deleteProbe = probe
        deleteProbe.removeValue(forKey: kSecValueData as String)
        SecItemDelete(deleteProbe as CFDictionary)
    }

    override func tearDown() {
        MockWebhookURLProtocol.reset()
        defaults.removePersistentDomain(forName: defaultsSuiteName)
        defaults = nil
        defaultsSuiteName = nil
        try? FileManager.default.removeItem(at: outboxDirectory)
        outboxDirectory = nil
        WebhookManager.keychainWriteString("", account: testAccount)
        UserDefaults.standard.removeObject(forKey: testLegacyKey)
        super.tearDown()
    }

    // MARK: - Keychain round-trip

    func testKeychainWriteThenReadReturnsSameValue() {
        WebhookManager.keychainWriteString("supersecret", account: testAccount)
        XCTAssertEqual(WebhookManager.keychainReadString(account: testAccount), "supersecret")
    }

    func testKeychainReadMissingReturnsNil() {
        XCTAssertNil(WebhookManager.keychainReadString(account: testAccount))
    }

    func testKeychainEmptyValueDeletes() {
        WebhookManager.keychainWriteString("first", account: testAccount)
        XCTAssertNotNil(WebhookManager.keychainReadString(account: testAccount))

        WebhookManager.keychainWriteString("", account: testAccount)
        XCTAssertNil(WebhookManager.keychainReadString(account: testAccount),
                     "Empty string must remove the keychain entry")
    }

    func testKeychainUpdateOverwritesPriorValue() {
        WebhookManager.keychainWriteString("first", account: testAccount)
        WebhookManager.keychainWriteString("second", account: testAccount)
        XCTAssertEqual(WebhookManager.keychainReadString(account: testAccount), "second")
    }

    func testKeychainHandlesUnicodeAndLongStrings() {
        let value = String(repeating: "🔐", count: 200) + "·secret·" + String(repeating: "x", count: 1000)
        WebhookManager.keychainWriteString(value, account: testAccount)
        XCTAssertEqual(WebhookManager.keychainReadString(account: testAccount), value)
    }

    // MARK: - loadCredential migration

    func testLoadCredentialReturnsKeychainValueWhenPresent() {
        WebhookManager.keychainWriteString("from-keychain", account: testAccount)
        UserDefaults.standard.set("from-defaults", forKey: testLegacyKey)

        let value = WebhookManager.loadCredential(
            account: testAccount,
            legacyKey: testLegacyKey,
            defaultValue: "fallback"
        )

        XCTAssertEqual(value, "from-keychain", "Keychain takes precedence over UserDefaults")
        XCTAssertEqual(UserDefaults.standard.string(forKey: testLegacyKey), "from-defaults",
                       "When keychain is already populated, UserDefaults is left alone")
    }

    func testLoadCredentialMigratesFromUserDefaults() {
        UserDefaults.standard.set("legacy-secret", forKey: testLegacyKey)

        let value = WebhookManager.loadCredential(
            account: testAccount,
            legacyKey: testLegacyKey,
            defaultValue: "fallback"
        )

        XCTAssertEqual(value, "legacy-secret")
        XCTAssertEqual(WebhookManager.keychainReadString(account: testAccount), "legacy-secret",
                       "Migrated value must be in Keychain")
        XCTAssertNil(UserDefaults.standard.string(forKey: testLegacyKey),
                     "Plaintext UserDefaults copy must be deleted after migration")
    }

    func testLoadCredentialReturnsDefaultWhenNothingStored() {
        let value = WebhookManager.loadCredential(
            account: testAccount,
            legacyKey: testLegacyKey,
            defaultValue: "fallback"
        )
        XCTAssertEqual(value, "fallback")
        XCTAssertNil(WebhookManager.keychainReadString(account: testAccount),
                     "Default fallback must not be persisted to Keychain")
    }

    func testLoadCredentialIgnoresEmptyLegacyValue() {
        UserDefaults.standard.set("", forKey: testLegacyKey)

        let value = WebhookManager.loadCredential(
            account: testAccount,
            legacyKey: testLegacyKey,
            defaultValue: "fallback"
        )

        XCTAssertEqual(value, "fallback", "Empty legacy string is not a credential")
        XCTAssertNil(WebhookManager.keychainReadString(account: testAccount))
    }

    func testLoadCredentialMigrationIsIdempotent() {
        UserDefaults.standard.set("once", forKey: testLegacyKey)

        let first = WebhookManager.loadCredential(
            account: testAccount,
            legacyKey: testLegacyKey,
            defaultValue: "fallback"
        )
        let second = WebhookManager.loadCredential(
            account: testAccount,
            legacyKey: testLegacyKey,
            defaultValue: "fallback"
        )

        XCTAssertEqual(first, "once")
        XCTAssertEqual(second, "once")
        XCTAssertNil(UserDefaults.standard.string(forKey: testLegacyKey))
    }

    // MARK: - KeychainKey account naming

    /// The Keychain account names are part of the on-device data contract —
    /// changing them silently would orphan every existing user's credentials.
    func testKeychainAccountNamesAreStable() {
        XCTAssertEqual(WebhookManager.keychainAccount(.authKey), "webhook.authKey")
        XCTAssertEqual(WebhookManager.keychainAccount(.authValue), "webhook.authValue")
        XCTAssertEqual(WebhookManager.keychainAccount(.authUsername), "webhook.authUsername")
    }

    func testLegacyDefaultsKeysMatchOriginalNames() {
        XCTAssertEqual(WebhookManager.legacyDefaultsKey(.authKey), "webhook.authKey")
        XCTAssertEqual(WebhookManager.legacyDefaultsKey(.authValue), "webhook.authValue")
        XCTAssertEqual(WebhookManager.legacyDefaultsKey(.authUsername), "webhook.authUsername")
    }

    // MARK: - Error sanitization

    func testSanitizeReplacesSecretWithMask() {
        let scrubbed = WebhookManager.sanitizeError(
            "Failed to load https://api.example.com?api_key=hunter2",
            masking: "hunter2"
        )
        XCTAssertEqual(scrubbed, "Failed to load https://api.example.com?api_key=***")
    }

    func testSanitizeReplacesAllOccurrences() {
        let scrubbed = WebhookManager.sanitizeError(
            "tried hunter2, then hunter2 again",
            masking: "hunter2"
        )
        XCTAssertEqual(scrubbed, "tried ***, then *** again")
    }

    func testSanitizeNoOpWhenSecretEmpty() {
        let message = "some error: token=abc"
        XCTAssertEqual(WebhookManager.sanitizeError(message, masking: ""), message)
    }

    func testSanitizeNoOpWhenSecretAbsent() {
        let message = "the request timed out"
        XCTAssertEqual(WebhookManager.sanitizeError(message, masking: "hunter2"), message)
    }

    func testSanitizeHandlesSpecialCharacterSecrets() {
        let secret = "a+b/c=d&e?f"
        let scrubbed = WebhookManager.sanitizeError(
            "url contains a+b/c=d&e?f in the query",
            masking: secret
        )
        XCTAssertEqual(scrubbed, "url contains *** in the query")
    }

    // MARK: - Delivery

    func testFlushBatchPostsPayloadAndClearsQueueOnSuccess() async {
        MockWebhookURLProtocol.enqueue(statusCode: 201)
        let manager = makeWebhookManager(retryPolicy: .init(maxAttempts: 1, baseDelay: 0, multiplier: 1))
        manager.urlString = "https://example.com/hooks/location"
        manager.enqueuePendingPoint(makePoint(latitude: 10.1, longitude: -20.2))

        await manager.flushBatch()

        XCTAssertEqual(manager.queuedPointCount, 0)
        XCTAssertNil(manager.lastError)
        XCTAssertNotNil(manager.lastSentAt)
        XCTAssertEqual(MockWebhookURLProtocol.postRequests.count, 1)
        XCTAssertEqual(MockWebhookURLProtocol.postRequests.first?.httpMethod, "POST")
        XCTAssertEqual(MockWebhookURLProtocol.postRequests.first?.value(forHTTPHeaderField: "Content-Type"), "application/json")

        let body = String(data: MockWebhookURLProtocol.postBodies.first ?? Data(), encoding: .utf8)
        XCTAssertTrue(body?.contains("10.1") == true)
        XCTAssertTrue(body?.contains("-20.2") == true)
    }

    func testFlushBatchRecordsAndPersistsLastStatusCode() async {
        MockWebhookURLProtocol.enqueue(statusCode: 201)
        let manager = makeWebhookManager(retryPolicy: .init(maxAttempts: 1, baseDelay: 0, multiplier: 1))
        manager.urlString = "https://example.com/hooks/location"
        manager.enqueuePendingPoint(makePoint())

        await manager.flushBatch()

        XCTAssertEqual(manager.lastStatusCode, 201)
        XCTAssertEqual(defaults.object(forKey: "webhook.lastStatusCode") as? Int, 201)
        XCTAssertEqual(WebhookManager.statusText(200), "200 OK")
        XCTAssertEqual(WebhookManager.statusText(299), "299")
    }

    func testClearQueueDiscardsWaitingPointsWithoutSending() {
        let manager = makeWebhookManager(retryPolicy: .init(maxAttempts: 1, baseDelay: 0, multiplier: 1))
        manager.urlString = "https://example.com/hooks/location"
        manager.enqueuePendingPoint(makePoint())
        manager.enqueuePendingPoint(makePoint())

        manager.clearQueue()

        XCTAssertEqual(manager.queuedPointCount, 0)
        XCTAssertTrue(MockWebhookURLProtocol.requests.isEmpty)
        XCTAssertNil(manager.lastSentAt)
    }

    func testFlushBatchRetainsQueueAndRecordsUserVisibleErrorOnNon2xx() async {
        MockWebhookURLProtocol.enqueue(statusCode: 500)
        let manager = makeWebhookManager(retryPolicy: .init(maxAttempts: 1, baseDelay: 0, multiplier: 1))
        manager.urlString = "https://example.com/hooks/location"
        manager.enqueuePendingPoint(makePoint())

        await manager.flushBatch()

        XCTAssertEqual(manager.queuedPointCount, 1)
        XCTAssertEqual(manager.lastError, "Server returned HTTP 500")
        XCTAssertNil(manager.lastSentAt)
        XCTAssertEqual(defaults.string(forKey: "webhook.lastError"), "Server returned HTTP 500")
        XCTAssertEqual(MockWebhookURLProtocol.postRequests.count, 1)
    }

    func testFlushBatchRetriesWithBackoffBeforeSuccess() async {
        for _ in 0..<3 { MockWebhookURLProtocol.enqueueReceipt(status: "capture_pending") }
        MockWebhookURLProtocol.enqueue(statusCode: 500)
        MockWebhookURLProtocol.enqueue(statusCode: 502)
        MockWebhookURLProtocol.enqueueAccepted()
        var requestedDelays: [TimeInterval] = []
        let manager = makeWebhookManager(
            retryPolicy: .init(maxAttempts: 3, baseDelay: 0.25, multiplier: 3),
            sleep: { requestedDelays.append($0) }
        )
        manager.urlString = "https://example.com/hooks/location"
        manager.enqueuePendingPoint(makePoint())

        await manager.flushBatch()

        XCTAssertEqual(MockWebhookURLProtocol.postRequests.count, 3)
        XCTAssertEqual(Set(MockWebhookURLProtocol.postBodies).count, 1)
        XCTAssertEqual(requestedDelays, [0.25, 0.75])
        XCTAssertEqual(manager.queuedPointCount, 0)
        XCTAssertNil(manager.lastError)
        XCTAssertNotNil(manager.lastSentAt)
    }

    func testTestConnectionThrowsUnauthorizedFor401() async {
        MockWebhookURLProtocol.enqueue(statusCode: 401)
        let manager = makeWebhookManager(retryPolicy: .init(maxAttempts: 1, baseDelay: 0, multiplier: 1))
        manager.urlString = "https://example.com/hooks/location"

        do {
            _ = try await manager.testConnection()
            XCTFail("Expected unauthorized webhook error")
        } catch {
            XCTAssertEqual(error.localizedDescription, "Unauthorized (HTTP 401). Check your credentials.")
        }
    }

    func testVisitsOnlyJSONExportIsDelivered() async throws {
        MockWebhookURLProtocol.enqueue(statusCode: 200)
        let manager = makeWebhookManager(retryPolicy: .init(maxAttempts: 1, baseDelay: 0, multiplier: 1))
        manager.urlString = "https://example.com/hooks/location"
        let visit = Visit(latitude: 0, longitude: 0,
                          arrivedAt: Date(timeIntervalSince1970: 1_776_000_000))

        try await manager.sendPoints([], visits: [visit])

        XCTAssertEqual(MockWebhookURLProtocol.postBodies.count, 1)
        let payload = try XCTUnwrap(JSONSerialization.jsonObject(with: MockWebhookURLProtocol.postBodies[0]) as? [String: Any])
        XCTAssertEqual(payload["totalVisits"] as? Int, 1)
        XCTAssertEqual((payload["visits"] as? [Any])?.count, 1)
        XCTAssertEqual(payload["totalPoints"] as? Int, 0)
        XCTAssertNotNil(manager.lastSentAt)
    }

    func testPointOnlyFormatReportsUnsupportedVisitsWithoutClaimingSuccess() async {
        let manager = makeWebhookManager(retryPolicy: .init(maxAttempts: 1, baseDelay: 0, multiplier: 1))
        manager.urlString = "https://example.com/hooks/location"
        manager.format = .owntracks
        do {
            try await manager.sendPoints([], visits: [Visit(latitude: 0, longitude: 0, arrivedAt: Date())])
            XCTFail("Visits must not silently become an empty point export")
        } catch {
            XCTAssertTrue(error.localizedDescription.contains("supports location points only"))
        }
        XCTAssertTrue(MockWebhookURLProtocol.requests.isEmpty)
        XCTAssertNil(manager.lastSentAt)
    }

    func testPendingPointsAndAcknowledgedCursorSurviveReopening() throws {
        let request = outboxRequest()
        let first = makePoint(), second = makePoint()
        let queue = try WebhookOutbox(directory: outboxDirectory)
        _ = try queue.enqueue([first, second, first], for: request)
        _ = try queue.prepare(body: Data("exact original".utf8), points: [first, second], visitCount: 0, for: request)
        let reopened = try WebhookOutbox(directory: outboxDirectory)
        let pending = try reopened.read(for: request)
        XCTAssertEqual(pending.pending.count, 2)
        XCTAssertEqual(pending.prepared?.body, Data("exact original".utf8))
        XCTAssertNil(pending.cursor)

        _ = try reopened.acknowledge(for: request, digest: XCTUnwrap(pending.prepared?.sha256), statusCode: 200)

        let settled = try WebhookOutbox(directory: outboxDirectory).read(for: request)
        XCTAssertTrue(settled.pending.isEmpty)
        XCTAssertNil(settled.prepared)
        XCTAssertEqual(settled.cursor?.timestamp, first.timestamp)
        XCTAssertEqual(settled.cursor?.pointIDs, Set([first.id, second.id]))
        XCTAssertTrue(settled.cursor?.includes(first) == true)
        XCTAssertFalse(settled.cursor?.includes(makePoint()) == true,
                       "A distinct point with the same timestamp must remain eligible")
    }

    func testRestartAfterLostAcknowledgementUsesReceiptWithoutAnotherPost() async throws {
        MockWebhookURLProtocol.enqueueReceipt(status: "capture_pending")
        MockWebhookURLProtocol.enqueueError(.timedOut)
        var manager: WebhookManager? = makeWebhookManager(retryPolicy: .init(maxAttempts: 1, baseDelay: 0, multiplier: 1))
        manager!.urlString = "https://example.com/hooks/location"
        manager!.enqueuePendingPoint(makePoint())
        await manager!.flushBatch()
        let original = try XCTUnwrap(MockWebhookURLProtocol.postBodies.first)
        XCTAssertEqual(manager!.queuedPointCount, 1)
        XCTAssertNil(manager!.lastSentAt)
        manager = nil

        MockWebhookURLProtocol.enqueueReceipt(status: "accepted")
        let reopened = makeWebhookManager(retryPolicy: .init(maxAttempts: 1, baseDelay: 0, multiplier: 1))
        await reopened.flushBatch()

        XCTAssertEqual(MockWebhookURLProtocol.postBodies, [original])
        XCTAssertEqual(reopened.queuedPointCount, 0)
        XCTAssertNotNil(reopened.lastSentAt)
        XCTAssertNil(try WebhookOutbox(directory: outboxDirectory).read(for: outboxRequest()).prepared)
    }

    func testRestartWithExplicitPendingReceiptSendsTheIdenticalOriginal() async throws {
        MockWebhookURLProtocol.enqueueReceipt(status: "capture_pending")
        MockWebhookURLProtocol.enqueueError(.networkConnectionLost)
        let first = makeWebhookManager(retryPolicy: .init(maxAttempts: 1, baseDelay: 0, multiplier: 1))
        first.urlString = "https://example.com/hooks/location"
        first.enqueuePendingPoint(makePoint())
        await first.flushBatch()
        let body = try XCTUnwrap(MockWebhookURLProtocol.postBodies.first)

        MockWebhookURLProtocol.enqueueReceipt(status: "capture_pending")
        MockWebhookURLProtocol.enqueueAccepted()
        let reopened = makeWebhookManager(retryPolicy: .init(maxAttempts: 1, baseDelay: 0, multiplier: 1))
        await reopened.flushBatch()

        XCTAssertEqual(MockWebhookURLProtocol.postBodies, [body, body])
        XCTAssertEqual(reopened.queuedPointCount, 0)
        XCTAssertEqual(Set(MockWebhookURLProtocol.postRequests.compactMap {
            $0.value(forHTTPHeaderField: "X-Whereday-Export-ID")
        }), [MockWebhookURLProtocol.exportID])
    }

    func testGenericUnknownDeliveryRemainsQueuedAcrossRestartAndClear() async throws {
        MockWebhookURLProtocol.enqueueError(.timedOut)
        let first = makeWebhookManager(retryPolicy: .init(maxAttempts: 3, baseDelay: 0, multiplier: 1))
        first.urlString = "https://example.com/hooks/location"
        first.enqueuePendingPoint(makePoint())
        await first.flushBatch()
        XCTAssertEqual(MockWebhookURLProtocol.postRequests.count, 1)
        let requestCount = MockWebhookURLProtocol.requests.count

        let reopened = makeWebhookManager(retryPolicy: .init(maxAttempts: 3, baseDelay: 0, multiplier: 1))
        await reopened.flushBatch()
        reopened.clearQueue()

        XCTAssertEqual(MockWebhookURLProtocol.requests.count, requestCount)
        XCTAssertEqual(reopened.queuedPointCount, 1)
        XCTAssertNil(reopened.lastSentAt)
        XCTAssertTrue(reopened.lastError?.contains("no uncertain upload was repeated") == true)
        XCTAssertTrue(try WebhookOutbox(directory: outboxDirectory).read(for: outboxRequest()).prepared?.attempted == true)
    }

    func testChangedReceiverAccountCannotAcknowledgeOrReplayUnknownDelivery() async {
        MockWebhookURLProtocol.enqueueReceipt(status: "capture_pending")
        MockWebhookURLProtocol.enqueueError(.timedOut)
        let first = makeWebhookManager(retryPolicy: .init(maxAttempts: 1, baseDelay: 0, multiplier: 1))
        first.urlString = "https://example.com/hooks/location"
        first.enqueuePendingPoint(makePoint())
        await first.flushBatch()

        MockWebhookURLProtocol.enqueueReceipt(status: "accepted", exportID: "restricted-export:different-account")
        let reopened = makeWebhookManager(retryPolicy: .init(maxAttempts: 1, baseDelay: 0, multiplier: 1))
        await reopened.flushBatch()

        XCTAssertEqual(MockWebhookURLProtocol.postRequests.count, 1)
        XCTAssertEqual(reopened.queuedPointCount, 1)
        XCTAssertNil(reopened.lastSentAt)
    }

    func testChangedCredentialsAndDestinationCannotReadAnOldQueue() throws {
        let queue = try WebhookOutbox(directory: outboxDirectory)
        var original = outboxRequest()
        original.setValue("test-secret-one", forHTTPHeaderField: "X-Custom-Auth")
        _ = try queue.enqueue([makePoint()], for: original)
        var changed = original
        changed.setValue("test-secret-two", forHTTPHeaderField: "X-Custom-Auth")
        XCTAssertTrue(try queue.read(for: changed).pending.isEmpty)
        changed = original
        changed.url = URL(string: "https://example.org/another-destination")!
        XCTAssertTrue(try queue.read(for: changed).pending.isEmpty)
        XCTAssertEqual(try queue.read(for: original).pending.count, 1)
        let file = try XCTUnwrap(FileManager.default.contentsOfDirectory(at: outboxDirectory, includingPropertiesForKeys: nil).first)
        let encoded = try String(contentsOf: file, encoding: .utf8)
        XCTAssertFalse(encoded.contains("test-secret-one"))
        XCTAssertFalse(encoded.contains("example.com"))
    }

    func testDamagedPreparedBytesAreHeldWithoutNetworkOrCursorAdvance() async throws {
        let queue = try WebhookOutbox(directory: outboxDirectory), request = outboxRequest()
        _ = try queue.enqueue([makePoint()], for: request)
        _ = try queue.prepare(body: Data("original".utf8), points: [makePoint()], visitCount: 0, for: request)
        let file = outboxDirectory.appendingPathComponent(try WebhookOutbox.binding(for: request) + ".json")
        var value = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: file)) as? [String: Any])
        var prepared = try XCTUnwrap(value["prepared"] as? [String: Any])
        prepared["body"] = Data("damaged".utf8).base64EncodedString()
        value["prepared"] = prepared
        try JSONSerialization.data(withJSONObject: value).write(to: file, options: .atomic)

        let manager = makeWebhookManager(retryPolicy: .init(maxAttempts: 1, baseDelay: 0, multiplier: 1))
        manager.urlString = "https://example.com/hooks/location"
        await manager.flushBatch()

        XCTAssertTrue(MockWebhookURLProtocol.requests.isEmpty)
        XCTAssertNil(manager.lastSentAt)
        XCTAssertThrowsError(try queue.read(for: request))
        XCTAssertTrue(FileManager.default.fileExists(atPath: file.path))
    }

    func testDisabledSenderKeepsPendingWorkWithoutNetwork() async {
        let manager = makeWebhookManager(retryPolicy: .init(maxAttempts: 1, baseDelay: 0, multiplier: 1))
        manager.urlString = "https://example.com/hooks/location"
        manager.enqueuePendingPoint(makePoint())
        manager.isEnabled = false
        await manager.flushBatch()
        XCTAssertEqual(manager.queuedPointCount, 1)
        XCTAssertTrue(MockWebhookURLProtocol.requests.isEmpty)
    }

    func testBacklogDrainsInBoundedBatchesWithoutAnotherLocationEvent() async throws {
        for _ in 0..<3 { MockWebhookURLProtocol.enqueue(statusCode: 200) }
        let manager = makeWebhookManager(retryPolicy: .init(maxAttempts: 1, baseDelay: 0, multiplier: 1))
        manager.urlString = "https://example.com/hooks/location"
        manager.batchCount = 2
        for index in 0..<5 { manager.enqueuePendingPoint(makePoint(latitude: Double(index))) }

        await manager.flushBatch()

        XCTAssertEqual(manager.queuedPointCount, 0)
        let counts = try MockWebhookURLProtocol.postBodies.map {
            (try JSONSerialization.jsonObject(with: $0) as? [String: Any])?["totalPoints"] as? Int
        }
        XCTAssertEqual(counts, [2, 2, 1])
        XCTAssertFalse(manager.isSending)
    }

    func testSameMIMEFormatChangeDuringPreflightHoldsOriginalWithoutPost() async throws {
        XCTAssertEqual(ExportFormat.json.mimeType, ExportFormat.owntracks.mimeType)
        let started = expectation(description: "Receipt request started")
        let release = DispatchSemaphore(value: 0)
        MockWebhookURLProtocol.enqueueReceipt(status: "capture_pending")
        MockWebhookURLProtocol.setBeforeResponse { request in
            if request.httpMethod == "GET" {
                started.fulfill()
                _ = release.wait(timeout: .now() + 5)
            }
        }
        let manager = makeWebhookManager(retryPolicy: .init(maxAttempts: 1, baseDelay: 0, multiplier: 1))
        manager.urlString = "https://example.com/hooks/location"
        manager.enqueuePendingPoint(makePoint())
        let send = Task { await manager.flushBatch() }
        await fulfillment(of: [started], timeout: 3)

        manager.format = .owntracks
        XCTAssertEqual(manager.queuedPointCount, 0, "The new format must have a distinct queue binding")
        release.signal()
        await send.value

        XCTAssertTrue(MockWebhookURLProtocol.postRequests.isEmpty)
        XCTAssertNil(manager.lastSentAt)
        manager.format = .json
        XCTAssertEqual(manager.queuedPointCount, 1)
        let prepared = try XCTUnwrap(WebhookOutbox(directory: outboxDirectory).read(for: outboxRequest()).prepared)
        XCTAssertFalse(prepared.attempted)
        XCTAssertNotNil(try JSONSerialization.jsonObject(with: prepared.body) as? [String: Any])
    }

    func testPointQueuedDuringGenericPreflightSurvivesAndDrainsInSameFlush() async {
        let started = expectation(description: "First generic preflight started")
        let release = DispatchSemaphore(value: 0)
        var intercepted = false
        MockWebhookURLProtocol.setBeforeResponse { request in
            if request.httpMethod == "GET", !intercepted {
                intercepted = true
                started.fulfill()
                _ = release.wait(timeout: .now() + 5)
            }
        }
        MockWebhookURLProtocol.enqueue(statusCode: 200)
        MockWebhookURLProtocol.enqueue(statusCode: 200)
        let manager = makeWebhookManager(retryPolicy: .init(maxAttempts: 1, baseDelay: 0, multiplier: 1))
        manager.urlString = "https://example.com/hooks/location"
        manager.batchCount = 1
        manager.enqueuePendingPoint(makePoint(latitude: 1))
        let send = Task { await manager.flushBatch() }
        await fulfillment(of: [started], timeout: 3)

        manager.enqueuePendingPoint(makePoint(latitude: 2))
        release.signal()
        await send.value

        XCTAssertEqual(MockWebhookURLProtocol.postRequests.count, 2)
        XCTAssertEqual(manager.queuedPointCount, 0)
        XCTAssertFalse(manager.isSending)
    }

    func testFreshManualRowsAndVisitRevisionProceedWhileOldHistoryIsUnknown() async throws {
        let manager = makeWebhookManager(retryPolicy: .init(maxAttempts: 1, baseDelay: 0, multiplier: 1))
        manager.urlString = "https://example.com/hooks/location"
        let oldPoint = makePoint(latitude: 1), freshPoint = makePoint(latitude: 2)
        let oldVisit = Visit(latitude: 3, longitude: 4, arrivedAt: Date(timeIntervalSince1970: 1_700_000_000), notes: "original")
        let newVisit = Visit(latitude: 5, longitude: 6, arrivedAt: Date(timeIntervalSince1970: 1_800_000_000), notes: "fresh")
        MockWebhookURLProtocol.enqueueError(.networkConnectionLost)
        do {
            try await manager.sendPoints([oldPoint], visits: [oldVisit], history: true)
            XCTFail("The unknown historical result must remain visible")
        } catch {}
        let original = try XCTUnwrap(MockWebhookURLProtocol.postBodies.first)
        let digest = WebhookOutbox.digest(original)

        MockWebhookURLProtocol.enqueue(statusCode: 200)
        do { try await manager.sendPoints([oldPoint, freshPoint], visits: [oldVisit, newVisit]) }
        catch { /* The older unknown still needs reconciliation. */ }
        XCTAssertEqual(MockWebhookURLProtocol.postBodies.count, 2)
        let fresh = try XCTUnwrap(JSONSerialization.jsonObject(with: MockWebhookURLProtocol.postBodies[1]) as? [String: Any])
        XCTAssertEqual(fresh["totalPoints"] as? Int, 1)
        XCTAssertEqual(fresh["totalVisits"] as? Int, 1)
        XCTAssertEqual((fresh["points"] as? [[String: Any]])?.first?["latitude"] as? Double, 2)
        XCTAssertEqual((fresh["visits"] as? [[String: Any]])?.first?["notes"] as? String, "fresh")

        oldVisit.notes = "corrected after the first snapshot"
        MockWebhookURLProtocol.enqueue(statusCode: 200)
        do { try await manager.sendPoints([oldPoint, freshPoint], visits: [oldVisit, newVisit]) }
        catch { /* An independent changed revision does not settle the old one. */ }
        XCTAssertEqual(MockWebhookURLProtocol.postBodies.count, 3)
        let correction = try XCTUnwrap(JSONSerialization.jsonObject(with: MockWebhookURLProtocol.postBodies[2]) as? [String: Any])
        XCTAssertEqual(correction["totalPoints"] as? Int, 0)
        XCTAssertEqual((correction["visits"] as? [[String: Any]])?.first?["notes"] as? String, oldVisit.notes)

        let queue = try WebhookOutbox(directory: outboxDirectory)
        try queue.activate(digest, for: outboxRequest())
        let retained = try XCTUnwrap(queue.read(for: outboxRequest()).prepared)
        XCTAssertEqual(retained.body, original)
        XCTAssertTrue(retained.attempted)
        XCTAssertNil(retained.receiverExportID)
        XCTAssertEqual(manager.queuedPointCount, 1)
    }

    func testFreshPointDuringHistoryPostRunsBeforeNextHistoryOperation() async throws {
        let request = outboxRequest(), queue = try WebhookOutbox(directory: outboxDirectory)
        for latitude in [10.0, 20.0] {
            let point = LocationPoint(latitude: latitude, longitude: 0,
                                      timestamp: Date(timeIntervalSince1970: 1_700_000_000 + latitude), horizontalAccuracy: 5)
            let body = try ExportService.exportLocationPointsToJSON(points: [point])
            _ = try queue.prepare(body: body, points: [point], visitCount: 0, for: request, history: true)
        }
        for _ in 0..<3 { MockWebhookURLProtocol.enqueue(statusCode: 200) }
        let started = expectation(description: "First history POST started")
        let release = DispatchSemaphore(value: 0)
        var intercepted = false
        MockWebhookURLProtocol.setBeforeResponse { request in
            if request.httpMethod == "POST", !intercepted {
                intercepted = true
                started.fulfill()
                _ = release.wait(timeout: .now() + 5)
            }
        }
        let manager = makeWebhookManager(retryPolicy: .init(maxAttempts: 1, baseDelay: 0, multiplier: 1))
        manager.urlString = "https://example.com/hooks/location"
        manager.batchCount = 1
        let send = Task { await manager.flushBatch() }
        await fulfillment(of: [started], timeout: 3)
        XCTAssertTrue(manager.isSending)
        manager.enqueuePendingPoint(makePoint(latitude: 99))
        XCTAssertEqual(try queue.unpreparedPoints(for: request).count, 1)
        release.signal()
        await send.value

        let order = try MockWebhookURLProtocol.postBodies.map {
            let value = try XCTUnwrap(JSONSerialization.jsonObject(with: $0) as? [String: Any])
            return (value["points"] as? [[String: Any]])?.first?["latitude"] as? Double
        }
        XCTAssertEqual(order, [20, 99, 10])
        XCTAssertEqual(manager.queuedPointCount, 0)
        XCTAssertFalse(manager.isSending)
    }

    func testAcceptedLegacyJSONVisitMembershipSurvivesBodyCleanupAndRestart() async throws {
        let request = outboxRequest(), queue = try WebhookOutbox(directory: outboxDirectory)
        let visit = Visit(latitude: 1, longitude: 2, arrivedAt: Date(timeIntervalSince1970: 1_700_000_000), notes: "legacy original")
        let body = try ExportService.exportToJSON(visits: [visit])
        var legacy = WebhookOutbox.State(binding: try WebhookOutbox.binding(for: request))
        legacy.prepared = .init(body: body, sha256: WebhookOutbox.digest(body), points: [], visitCount: 1,
                                attempted: true, receiverExportID: MockWebhookURLProtocol.exportID)
        let stateURL = outboxDirectory.appendingPathComponent(legacy.binding + ".json")
        // A genuine version-one state has no independent operation metadata or
        // native visit revision IDs. Do not pre-migrate it through queue.save.
        try JSONEncoder().encode(legacy).write(to: stateURL, options: .atomic)
        MockWebhookURLProtocol.enqueueReceipt(status: "accepted")
        let first = makeWebhookManager(retryPolicy: .init(maxAttempts: 1, baseDelay: 0, multiplier: 1))
        first.urlString = "https://example.com/hooks/location"
        await first.flushBatch()
        XCTAssertNil(first.lastError)
        XCTAssertNil(try queue.read(for: request).prepared)
        XCTAssertTrue(MockWebhookURLProtocol.postRequests.isEmpty)

        let reopened = makeWebhookManager(retryPolicy: .init(maxAttempts: 1, baseDelay: 0, multiplier: 1))
        reopened.urlString = "https://example.com/hooks/location"
        try await reopened.sendPoints([], visits: [visit])
        XCTAssertEqual(MockWebhookURLProtocol.requests.count, 1, "No new GET or POST may recreate the accepted legacy visit")
        let membership = try WebhookOutbox(directory: outboxDirectory).sourceMembership(for: request)
        XCTAssertEqual(membership.legacyVisits.count, 1)
        XCTAssertFalse(membership.unknownVisits)
    }

    func testOpaqueLegacyVisitHoldsVisitsWhileIdentifiedFreshPointsProceed() async throws {
        var request = outboxRequest()
        request.setValue(ExportFormat.csv.mimeType, forHTTPHeaderField: "Content-Type")
        request.setValue("csv", forHTTPHeaderField: "X-Whereday-Export-Format")
        let queue = try WebhookOutbox(directory: outboxDirectory)
        let visit = Visit(latitude: 1, longitude: 2, arrivedAt: Date(timeIntervalSince1970: 1_700_000_000), notes: "legacy original")
        let original = ExportService.exportToCSV(visits: [visit])
        let digest = WebhookOutbox.digest(original)
        var legacy = WebhookOutbox.State(binding: try WebhookOutbox.binding(for: request))
        legacy.prepared = .init(body: original, sha256: digest, points: [], visitCount: 1, attempted: true)
        try JSONEncoder().encode(legacy).write(to: outboxDirectory.appendingPathComponent(legacy.binding + ".json"), options: .atomic)
        MockWebhookURLProtocol.enqueue(statusCode: 200)
        let manager = makeWebhookManager(retryPolicy: .init(maxAttempts: 1, baseDelay: 0, multiplier: 1))
        manager.urlString = "https://example.com/hooks/location"
        manager.format = .csv
        let fresh = makePoint(latitude: 9)
        do {
            try await manager.sendPoints([fresh], visits: [visit])
            XCTFail("Opaque legacy visit membership must be explicitly held")
        } catch WebhookOutbox.QueueError.legacyVisitsUnavailable {}
        catch { XCTFail("Unexpected error: \(error)") }
        XCTAssertEqual(MockWebhookURLProtocol.postBodies.count, 1)
        XCTAssertNotEqual(MockWebhookURLProtocol.postBodies.first, original)
        XCTAssertNotNil(manager.lastSentAt, "The independently identified point was delivered")
        try queue.activate(digest, for: request)
        let retained = try XCTUnwrap(queue.read(for: request).prepared)
        XCTAssertEqual(retained.body, original)
        XCTAssertTrue(retained.attempted)
        XCTAssertEqual(retained.visitCount, 1)
        let membership = try WebhookOutbox(directory: outboxDirectory).sourceMembership(for: request)
        XCTAssertTrue(membership.unknownVisits)
        XCTAssertTrue(membership.points.contains(fresh.id))
    }

    private func outboxRequest() -> URLRequest {
        var request = URLRequest(url: URL(string: "https://example.com/hooks/location")!)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("json", forHTTPHeaderField: "X-Whereday-Export-Format")
        return request
    }

    private func makeWebhookManager(
        retryPolicy: WebhookManager.RetryPolicy,
        sleep: @escaping (TimeInterval) async -> Void = { _ in }
    ) -> WebhookManager {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [MockWebhookURLProtocol.self]
        let session = URLSession(configuration: config)
        return WebhookManager(
            defaults: defaults,
            urlSession: session,
            outboxDirectory: outboxDirectory,
            retryPolicy: retryPolicy,
            sleep: sleep
        )
    }

    private func makePoint(latitude: Double = 37.7749, longitude: Double = -122.4194) -> LocationPoint {
        LocationPoint(
            latitude: latitude,
            longitude: longitude,
            timestamp: Date(timeIntervalSince1970: 1_776_000_000),
            horizontalAccuracy: 5
        )
    }
}

private final class MockWebhookURLProtocol: URLProtocol {
    private struct Response {
        let statusCode: Int
        let body: Data
        var error: URLError?
        var acceptance = false
    }

    private struct Receipt {
        let status: String
        let exportID: String
    }

    static let exportID = "restricted-export:test-account-fixed-identity"
    private static let lock = NSLock()
    private static var queuedResponses: [Response] = []
    private static var queuedReceipts: [Receipt] = []
    private static var beforeResponse: ((URLRequest) -> Void)?
    private(set) static var requests: [URLRequest] = []
    private(set) static var requestBodies: [Data] = []

    static func reset() {
        lock.withLock {
            queuedResponses = []
            queuedReceipts = []
            beforeResponse = nil
            requests = []
            requestBodies = []
        }
    }

    static var postRequests: [URLRequest] { lock.withLock { requests.filter { $0.httpMethod == "POST" } } }
    static var postBodies: [Data] {
        lock.withLock { zip(requests, requestBodies).filter { $0.0.httpMethod == "POST" }.map { $0.1 } }
    }

    static func enqueueReceipt(status: String, exportID: String = MockWebhookURLProtocol.exportID) {
        lock.withLock { queuedReceipts.append(Receipt(status: status, exportID: exportID)) }
    }

    static func enqueueAccepted() {
        lock.withLock { queuedResponses.append(Response(statusCode: 200, body: Data(), acceptance: true)) }
    }

    static func enqueueError(_ code: URLError.Code) {
        lock.withLock { queuedResponses.append(Response(statusCode: 0, body: Data(), error: URLError(code))) }
    }

    static func setBeforeResponse(_ action: @escaping (URLRequest) -> Void) {
        lock.withLock { beforeResponse = action }
    }

    static func enqueue(statusCode: Int, body: Data = Data()) {
        lock.withLock {
            queuedResponses.append(Response(statusCode: statusCode, body: body))
        }
    }

    override class func canInit(with request: URLRequest) -> Bool {
        true
    }

    override class func canonicalRequest(for request: URLRequest) -> URLRequest {
        request
    }

    override func startLoading() {
        let body = Self.bodyData(from: request)
        let next: Response? = Self.lock.withLock {
            Self.requests.append(request)
            Self.requestBodies.append(body)
            if request.httpMethod == "GET" {
                guard !Self.queuedReceipts.isEmpty else { return Response(statusCode: 405, body: Data()) }
                let receipt = Self.queuedReceipts.removeFirst()
                let json: [String: Any] = [
                    "status": receipt.status,
                    "sha256": request.value(forHTTPHeaderField: "X-Whereday-Export-SHA256") ?? "",
                    "capture": ["export_id": receipt.exportID], "retry_same_original": true,
                ]
                return Response(statusCode: 200, body: try! JSONSerialization.data(withJSONObject: json))
            }
            return Self.queuedResponses.isEmpty ? nil : Self.queuedResponses.removeFirst()
        }

        guard let next else {
            client?.urlProtocol(self, didFailWithError: URLError(.badServerResponse))
            return
        }

        Self.lock.withLock { Self.beforeResponse }?(request)

        if let error = next.error {
            client?.urlProtocol(self, didFailWithError: error)
            return
        }

        let response = HTTPURLResponse(
            url: request.url!,
            statusCode: next.statusCode,
            httpVersion: "HTTP/1.1",
            headerFields: nil
        )!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        let reply: Data
        if next.acceptance {
            let json: [String: Any] = [
                "status": "accepted", "sha256": SHA256.hash(data: body).map { String(format: "%02x", $0) }.joined(),
                "capture": ["export_id": request.value(forHTTPHeaderField: "X-Whereday-Export-ID") ?? ""],
            ]
            reply = try! JSONSerialization.data(withJSONObject: json)
        } else { reply = next.body }
        client?.urlProtocol(self, didLoad: reply)
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}

    private static func bodyData(from request: URLRequest) -> Data {
        if let body = request.httpBody {
            return body
        }
        guard let stream = request.httpBodyStream else {
            return Data()
        }
        stream.open()
        defer { stream.close() }

        var data = Data()
        let bufferSize = 1024
        let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: bufferSize)
        defer { buffer.deallocate() }

        while stream.hasBytesAvailable {
            let count = stream.read(buffer, maxLength: bufferSize)
            guard count > 0 else { break }
            data.append(buffer, count: count)
        }
        return data
    }
}

private extension NSLock {
    func withLock<T>(_ body: () -> T) -> T {
        lock()
        defer { unlock() }
        return body()
    }
}


@MainActor
final class WebhookContinuationTests: XCTestCase {
    private func request() -> URLRequest {
        var value = URLRequest(url: URL(string: "https://example.com/location")!)
        value.httpMethod = "POST"
        value.setValue("application/json", forHTTPHeaderField: "Content-Type")
        value.setValue("Bearer fabricated-fixture", forHTTPHeaderField: "Authorization")
        return value
    }

    private func fixture(_ count: Int = 20, visits: Int = 3) throws -> (Data, [LocationPoint]) {
        let points = (0..<count).map {
            LocationPoint(latitude: 1, longitude: 2,
                          timestamp: Date(timeIntervalSince1970: 1_700_000_000 + Double($0)), horizontalAccuracy: 5)
        }
        let records = points.enumerated().map { index, point -> [String: Any] in
            ["timestampUnix": point.timestamp.timeIntervalSince1970, "nativeID": point.id.uuidString,
             "latitude": point.latitude, "longitude": point.longitude, "sourceIndex": index,
             "unknown": ["original": String(repeating: "u", count: 40)]]
        }
        let body = try JSONSerialization.data(withJSONObject: [
            "exportDate": "2026-11-22T12:00:00Z", "totalPoints": count, "points": records,
            "totalVisits": visits,
            "visits": (0..<visits).map { ["arrivalDate": "2020-01-01T00:00:00Z", "nativeID": "visit-\($0)", "notes": "complete"] },
            "unknownExportField": ["keep": true]
        ])
        return (body, points)
    }

    func testFreshOperationBypassesUnknownHistoryAndReopensItsExactReceipt() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let queue = try WebhookOutbox(directory: root, maximumPayloadBytes: 900)
        let (body, points) = try fixture(), request = request()
        _ = try queue.prepare(body: body, points: points, visitCount: 3, for: request, history: true)
        let oldID = try XCTUnwrap(queue.nextDigest(for: request, excluding: []))
        try queue.activate(oldID, for: request)
        var state = try queue.read(for: request)
        state.prepared?.attempted = true
        state.prepared?.receiverExportID = "restricted-export:original-account"
        state.prepared?.membership = .init(exportID: "restricted-export:original-account", nextCursor: 1, total: 5)
        let original = try XCTUnwrap(state.prepared?.body)
        try queue.save(state)

        let fresh = LocationPoint(latitude: 1, longitude: 2, timestamp: Date(timeIntervalSince1970: 1_800_000_000), horizontalAccuracy: 5)
        let freshBody = try JSONSerialization.data(withJSONObject: ["exportDate": "2026-11-22T12:01:00Z", "totalPoints": 1,
             "points": [["latitude": 1, "longitude": 2, "timestampUnix": fresh.timestamp.timeIntervalSince1970]]])
        _ = try queue.prepare(body: freshBody, points: [fresh], visitCount: 0, for: request)
        let freshID = try XCTUnwrap(queue.nextDigest(for: request, excluding: []))
        XCTAssertEqual(freshID, WebhookOutbox.digest(freshBody))
        XCTAssertNotEqual(freshID, oldID)
        try queue.activate(freshID, for: request)
        _ = try queue.acknowledge(for: request, digest: freshID, statusCode: 200)

        let reopened = try WebhookOutbox(directory: root, maximumPayloadBytes: 900)
        try reopened.activate(oldID, for: request)
        let recovered = try XCTUnwrap(reopened.read(for: request).prepared)
        XCTAssertEqual(recovered.body, original)
        XCTAssertEqual(recovered.sha256, oldID)
        XCTAssertEqual(recovered.receiverExportID, "restricted-export:original-account")
        XCTAssertTrue(recovered.attempted)
        XCTAssertEqual(recovered.membership?.nextCursor, 1)
        XCTAssertTrue(try reopened.hasHistory(for: request))
        var changed = request
        changed.setValue("Bearer other-fabricated-account", forHTTPHeaderField: "Authorization")
        XCTAssertNil(try reopened.nextDigest(for: changed, excluding: []))
    }

    func testEveryPreparedChunkSurvivesRestartWithoutReformatting() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let (body, points) = try fixture(), request = request()
        let queue = try WebhookOutbox(directory: root, maximumPayloadBytes: 900)
        _ = try queue.prepare(body: body, points: points, visitCount: 3, for: request, history: true)
        var seen = Set<String>(), pointIDs = Set<UUID>(), visits = 0
        while let id = try queue.nextDigest(for: request, excluding: seen) {
            seen.insert(id)
            let reopened = try WebhookOutbox(directory: root, maximumPayloadBytes: 900)
            try reopened.activate(id, for: request)
            let operation = try XCTUnwrap(reopened.read(for: request).prepared)
            XCTAssertEqual(operation.sha256, WebhookOutbox.digest(operation.body))
            XCTAssertLessThanOrEqual(operation.body.count, 900)
            pointIDs.formUnion(operation.points.map(\.id)); visits += operation.visitCount
            _ = try reopened.acknowledge(for: request, digest: id, statusCode: 200)
        }
        XCTAssertGreaterThan(seen.count, 1)
        XCTAssertEqual(pointIDs, Set(points.map(\.id)))
        XCTAssertEqual(visits, 3)
        XCTAssertFalse(try queue.hasHistory(for: request))
        XCTAssertEqual(try queue.read(for: request).queuedPointCount, 0)
    }

    func testReceiptSurvivesInterruptedCursorCommitWithoutResubmission() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let (body, points) = try fixture(1, visits: 0), request = request()
        let queue = try WebhookOutbox(directory: root)
        _ = try queue.prepare(body: body, points: points, visitCount: 0, for: request)
        let stateURL = root.appendingPathComponent(try WebhookOutbox.binding(for: request) + ".json")
        let beforeCursorCommit = try Data(contentsOf: stateURL)
        _ = try queue.acknowledge(for: request, digest: WebhookOutbox.digest(body), statusCode: 200)
        try beforeCursorCommit.write(to: stateURL, options: .atomic)
        let reopened = try WebhookOutbox(directory: root)
        XCTAssertNil(try reopened.nextDigest(for: request, excluding: []))
        let repaired = try reopened.read(for: request)
        XCTAssertNil(repaired.prepared)
        XCTAssertEqual(repaired.cursor?.pointIDs, Set(points.map(\.id)))
        XCTAssertEqual(repaired.lastStatusCode, 200)
    }
}

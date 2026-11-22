import Foundation
import Combine
import Security
import SwiftData

/// HTTP webhook delivery of location data to a user-configured endpoint.
///
/// Supports OwnTracks, Overland, GPX, KML, GeoJSON, JSON, CSV, and Markdown payload formats.
/// Multiple auth methods (none, API key query param, Bearer, Basic, custom header).
/// Multiple send modes (realtime per-point, batch count, batch time, manual).
///
/// Privacy: entirely opt-in, disabled by default. When enabled, a prominent
/// warning tells the user their location data will be sent off-device.
@MainActor
final class WebhookManager: ObservableObject {
    static let shared = WebhookManager()

    struct RetryPolicy {
        let maxAttempts: Int
        let baseDelay: TimeInterval
        let multiplier: Double

        static let `default` = RetryPolicy(maxAttempts: 3, baseDelay: 1, multiplier: 2)

        func delay(beforeAttempt attempt: Int) -> TimeInterval {
            guard attempt > 1 else { return 0 }
            return baseDelay * pow(multiplier, Double(attempt - 2))
        }
    }

    // MARK: - Auth types

    enum AuthType: String, CaseIterable, Identifiable {
        case none
        case apiKeyQuery
        case bearer
        case basic
        case customHeader

        var id: String { rawValue }

        var label: String {
            switch self {
            case .none: return String(localized: "NONE")
            case .apiKeyQuery: return String(localized: "API KEY (QUERY)")
            case .bearer: return String(localized: "BEARER TOKEN")
            case .basic: return String(localized: "BASIC AUTH")
            case .customHeader: return String(localized: "CUSTOM HEADER")
            }
        }
    }

    enum SendMode: String, CaseIterable, Identifiable {
        case realtime
        case batchCount
        case batchTime
        case manual

        var id: String { rawValue }

        var label: String {
            switch self {
            case .realtime: return String(localized: "REAL-TIME")
            case .batchCount: return String(localized: "BY COUNT")
            case .batchTime: return String(localized: "BY TIME")
            case .manual: return String(localized: "MANUAL")
            }
        }
    }

    // MARK: - Published state

    @Published var isEnabled: Bool {
        didSet { defaults.set(isEnabled, forKey: Self.key(.enabled)); syncObservation(); syncTimer() }
    }
    @Published var urlString: String {
        didSet { defaults.set(urlString, forKey: Self.key(.url)); configurationChanged() }
    }
    @Published var format: ExportFormat {
        didSet { defaults.set(format.token, forKey: Self.key(.format)); configurationChanged() }
    }
    @Published var authType: AuthType {
        didSet { defaults.set(authType.rawValue, forKey: Self.key(.authType)); configurationChanged() }
    }
    @Published var authKey: String {
        didSet { Self.keychainWriteString(authKey, account: Self.keychainAccount(.authKey)); configurationChanged() }
    }
    @Published var authValue: String {
        didSet { Self.keychainWriteString(authValue, account: Self.keychainAccount(.authValue)); configurationChanged() }
    }
    @Published var authUsername: String {
        didSet { Self.keychainWriteString(authUsername, account: Self.keychainAccount(.authUsername)); configurationChanged() }
    }
    @Published var sendMode: SendMode {
        didSet { defaults.set(sendMode.rawValue, forKey: Self.key(.sendMode)); syncObservation(); syncTimer() }
    }
    @Published var batchCount: Int {
        didSet { defaults.set(batchCount, forKey: Self.key(.batchCount)) }
    }
    @Published var batchTimeMinutes: Int {
        didSet { defaults.set(batchTimeMinutes, forKey: Self.key(.batchTimeMinutes)); syncTimer() }
    }

    @Published private(set) var lastSentAt: Date?
    /// HTTP status of the last successful delivery, shown as "LAST SENT 14:05 · 200 OK".
    @Published private(set) var lastStatusCode: Int?
    @Published private(set) var lastError: String?
    @Published private(set) var queuedPointCount: Int = 0
    @Published private(set) var isSending: Bool = false

    // MARK: - Private

    private let defaults: UserDefaults
    private var cancellables = Set<AnyCancellable>()
    private var flushTimer: Timer?
    private weak var modelContainer: ModelContainer?
    private weak var attachedLocationManager: LocationManager?
    private let outbox: WebhookOutbox?
    private var urlSession: URLSession!
    private let retryPolicy: RetryPolicy
    private let sleep: (TimeInterval) async -> Void
    private var isDraining = false
    private var deliveryActive = false

    private enum DefaultsKey: String {
        case enabled, url, format, authType
        case sendMode, batchCount, batchTimeMinutes
        case lastSentAt, lastError, lastStatusCode
    }

    enum KeychainKey: String {
        case authKey, authValue, authUsername
    }

    private static func key(_ k: DefaultsKey) -> String { "webhook.\(k.rawValue)" }
    static func keychainAccount(_ k: KeychainKey) -> String { "webhook.\(k.rawValue)" }
    static func legacyDefaultsKey(_ k: KeychainKey) -> String { "webhook.\(k.rawValue)" }

    init(
        defaults: UserDefaults = .standard,
        urlSession: URLSession? = nil,
        outboxDirectory: URL? = nil,
        retryPolicy: RetryPolicy = .default,
        sleep: @escaping (TimeInterval) async -> Void = { delay in
            try? await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000))
        }
    ) {
        self.defaults = defaults
        self.outbox = try? WebhookOutbox(directory: outboxDirectory)
        self.retryPolicy = retryPolicy
        self.sleep = sleep
        let d = defaults
        self.isEnabled = d.bool(forKey: Self.key(.enabled))
        self.urlString = d.string(forKey: Self.key(.url)) ?? ""
        self.format = Self.formatFromToken(d.string(forKey: Self.key(.format)))
        self.authType = AuthType(rawValue: d.string(forKey: Self.key(.authType)) ?? "") ?? .none

        self.authKey = Self.loadCredential(.authKey, defaults: d, defaultValue: "api_key")
        self.authValue = Self.loadCredential(.authValue, defaults: d, defaultValue: "")
        self.authUsername = Self.loadCredential(.authUsername, defaults: d, defaultValue: "")

        self.sendMode = SendMode(rawValue: d.string(forKey: Self.key(.sendMode)) ?? "") ?? .realtime
        self.batchCount = d.object(forKey: Self.key(.batchCount)) as? Int ?? 10
        self.batchTimeMinutes = d.object(forKey: Self.key(.batchTimeMinutes)) as? Int ?? 5
        self.lastSentAt = d.object(forKey: Self.key(.lastSentAt)) as? Date
        self.lastStatusCode = d.object(forKey: Self.key(.lastStatusCode)) as? Int
        self.lastError = d.string(forKey: Self.key(.lastError))

        if let urlSession {
            self.urlSession = urlSession
        } else {
            let config = URLSessionConfiguration.ephemeral
            config.timeoutIntervalForRequest = 30
            config.timeoutIntervalForResource = 60
            self.urlSession = URLSession(configuration: config)
        }

        refreshQueue()
        syncTimer()
    }

    /// Read a credential from Keychain. If absent but a non-empty legacy
    /// UserDefaults value exists, migrate it into Keychain and clear the
    /// plaintext copy.
    static func loadCredential(
        account: String,
        legacyKey: String,
        defaultValue: String,
        defaults: UserDefaults = .standard
    ) -> String {
        if let stored = keychainReadString(account: account) {
            return stored
        }
        if let legacy = defaults.string(forKey: legacyKey), !legacy.isEmpty {
            keychainWriteString(legacy, account: account)
            defaults.removeObject(forKey: legacyKey)
            return legacy
        }
        return defaultValue
    }

    private static func loadCredential(_ key: KeychainKey, defaults: UserDefaults, defaultValue: String) -> String {
        loadCredential(
            account: keychainAccount(key),
            legacyKey: legacyDefaultsKey(key),
            defaultValue: defaultValue,
            defaults: defaults
        )
    }

    // MARK: - Wiring

    /// Must be called once on app launch so the manager can observe location updates.
    func attach(modelContainer: ModelContainer, locationManager: LocationManager) {
        self.modelContainer = modelContainer
        self.attachedLocationManager = locationManager
        syncObservation(locationManager: locationManager)
        Task { @MainActor [weak self] in await self?.resumeAutomaticWork() }
    }

    private func syncObservation(locationManager: LocationManager? = nil) {
        cancellables.removeAll()
        guard isEnabled else { return }

        guard let lm = locationManager ?? attachedLocationManager else { return }
        armCursorIfNeeded()

        // Batch modes need the same native saved-point observation as realtime.
        // Manual mode resumes only work the user had already prepared.
        if sendMode != .manual {
            lm.$locationPointsSavedCount
                .dropFirst()
                .receive(on: DispatchQueue.main)
                .sink { [weak self] _ in
                    Task { @MainActor in
                        await self?.onNewPoint(locationManager: lm)
                    }
                }
                .store(in: &cancellables)
        }
        NotificationCenter.default.publisher(for: .appDidBecomeActive)
            .receive(on: DispatchQueue.main)
            .sink { [weak self] _ in
                Task { @MainActor in await self?.resumeAutomaticWork() }
            }
            .store(in: &cancellables)
    }

    private func syncTimer() {
        flushTimer?.invalidate()
        flushTimer = nil
        guard isEnabled, sendMode == .batchTime, batchTimeMinutes > 0 else { return }
        flushTimer = Timer.scheduledTimer(
            withTimeInterval: TimeInterval(batchTimeMinutes * 60),
            repeats: true
        ) { [weak self] _ in
            Task { @MainActor in await self?.flushBatch() }
        }
    }

    // MARK: - Sending

    private func onNewPoint(locationManager: LocationManager) async {
        guard isEnabled, sendMode != .manual,
              let context = modelContainer?.mainContext else { return }
        do {
            let request = try configuredRequest(), queue = try requiredOutbox()
            let state = try queue.read(for: request)
            guard let cursor = state.cursor else { armCursorIfNeeded(); return }
            let sentinel = cursor.timestamp
            let descriptor = FetchDescriptor<LocationPoint>(
                predicate: #Predicate<LocationPoint> { $0.timestamp >= sentinel },
                sortBy: [SortDescriptor(\.timestamp, order: .forward)]
            )
            let showOutliers = defaults.bool(forKey: "showOutliers")
            let points = try context.fetch(descriptor).filter {
                !cursor.includes($0) && (!$0.isOutlier || showOutliers)
            }
            let saved = try queue.enqueue(points, for: request)
            queuedPointCount = saved.queuedPointCount
            if saved.prepared != nil || sendMode == .realtime || saved.pending.count >= max(1, batchCount) {
                await flushBatch()
            }
        } catch {
            recordError(error.localizedDescription)
        }
    }

    /// Each round gives fresh source records first service and visits each
    /// independent original once. Unknown history retains its exact identity.
    func flushBatch() async {
        do { try await drainPrepared() }
        catch { recordError(error.localizedDescription) }
        refreshQueue()
    }

    private func drainPrepared() async throws {
        guard isEnabled else { throw WebhookOutbox.QueueError.disabled }
        guard !deliveryActive, !isDraining else { return }
        isDraining = true; isSending = true
        defer { isDraining = false; isSending = false; refreshQueue() }
        let request = try configuredRequest(), queue = try requiredOutbox()
        var visited = Set<String>()
        var firstFailure: Error?
        while true {
            try validateCurrentSettings(request)
            try Task.checkCancellation()
            let points = Array(try queue.unpreparedPoints(for: request).prefix(max(1, batchCount)))
            if !points.isEmpty {
                let body = try formatPayload(points: points)
                _ = try queue.prepare(body: body, points: points, visitCount: 0, for: request)
            }
            guard let digest = try queue.nextDigest(for: request, excluding: visited) else { break }
            visited.insert(digest)
            do {
                try queue.activate(digest, for: request)
                // A historical failure gets one opportunity in this round.
                // Every continuation still goes through the exact receipt.
                let history = try queue.read(for: request).prepared?.history == true
                try await deliverPrepared(request: request, maximumAttempts: history ? 1 : nil)
            } catch {
                if firstFailure == nil { firstFailure = error }
            }
            await Task.yield()
        }
        if try queue.damagedOperationCount(for: request) > 0, firstFailure == nil {
            firstFailure = WebhookOutbox.QueueError.unavailable
        }
        if let firstFailure { throw firstFailure }
    }

    func enqueuePendingPoint(_ point: LocationPoint) {
        do {
            let state = try requiredOutbox().enqueue([point], for: configuredRequest())
            queuedPointCount = state.queuedPointCount
        } catch { recordError(error.localizedDescription) }
    }

    /// Discards waiting points without sending them. Saved location history is untouched.
    func clearQueue() {
        guard !isSending else { return }
        do {
            let state = try requiredOutbox().clearWaiting(for: configuredRequest())
            queuedPointCount = state.queuedPointCount
            if state.prepared != nil { recordError(WebhookOutbox.QueueError.recoveryUnavailable.localizedDescription) }
        } catch { recordError(error.localizedDescription) }
    }

    /// Send a manual export of all saved data.
    func sendNow() async {
        guard !isSending, let context = modelContainer?.mainContext else { return }
        do {
            let request = try configuredRequest()
            if try requiredOutbox().hasHistory(for: request) {
                try await drainPrepared()
                return
            }
            let visits = try context.fetch(FetchDescriptor<Visit>())
            let points = try context.fetch(FetchDescriptor<LocationPoint>())
            try await sendPoints(points, visits: visits, history: true)
        } catch {
            recordError(error.localizedDescription)
        }
    }

    private func resumeAutomaticWork() async {
        guard isEnabled, !isSending else { return }
        if let locationManager = attachedLocationManager, sendMode != .manual {
            await onNewPoint(locationManager: locationManager)
        }
        await flushBatch()
    }

    private func armCursorIfNeeded() {
        guard isEnabled, sendMode != .manual, attachedLocationManager != nil, buildURL() != nil else { return }
        do {
            let request = try configuredRequest(), queue = try requiredOutbox()
            var state = try queue.read(for: request)
            if state.cursor == nil {
                // Arm at enable/attach, before the first point arrives. Relaunch
                // reuses the saved cursor; it never skips the first new tick.
                state.cursor = .init(timestamp: Date(), pointIDs: [])
                try queue.save(state)
            }
        } catch { recordError(error.localizedDescription) }
    }

    private func configurationChanged() {
        armCursorIfNeeded()
        refreshQueue()
    }

    private func refreshQueue() {
        guard buildURL() != nil else { queuedPointCount = 0; return }
        do {
            let state = try requiredOutbox().read(for: configuredRequest())
            queuedPointCount = state.queuedPointCount
            if let date = state.lastSentAt {
                lastSentAt = date; lastStatusCode = state.lastStatusCode
            }
        } catch { recordError(error.localizedDescription) }
    }

    private func requiredOutbox() throws -> WebhookOutbox {
        guard let outbox else { throw WebhookOutbox.QueueError.unavailable }
        return outbox
    }

    /// Test the configured endpoint with a minimal payload.
    func testConnection() async throws -> String {
        let fakePoint = LocationPoint(
            latitude: 0,
            longitude: 0,
            timestamp: Date(),
            horizontalAccuracy: 0
        )
        let body = try formatPayload(points: [fakePoint])
        guard let url = buildURL() else {
            throw WebhookError.invalidURL
        }
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.httpBody = body
        request.setValue(format.mimeType, forHTTPHeaderField: "Content-Type")
        request.setValue("Whereday/\(AppInfo.version)", forHTTPHeaderField: "User-Agent")
        applyAuth(to: &request)

        let (_, response) = try await urlSession.data(for: request)
        guard let httpResponse = response as? HTTPURLResponse else {
            throw WebhookError.httpError(0)
        }
        if (200...299).contains(httpResponse.statusCode) {
            return String(localized: "Connected (HTTP \(httpResponse.statusCode))")
        } else if httpResponse.statusCode == 401 {
            throw WebhookError.unauthorized
        } else {
            throw WebhookError.httpError(httpResponse.statusCode)
        }
    }

    // MARK: - Core send

    func sendPoints(_ points: [LocationPoint], visits: [Visit] = [], history: Bool = false) async throws {
        guard !points.isEmpty || !visits.isEmpty else { return }
        guard isEnabled else { throw WebhookOutbox.QueueError.disabled }
        guard !deliveryActive, !isDraining else { throw WebhookOutbox.QueueError.busy }
        if points.isEmpty && (format == .owntracks || format == .overland) {
            throw WebhookOutbox.QueueError.unsupportedVisits
        }
        let request = try configuredRequest()
        let body = try formatPayload(points: points, visits: visits)
        _ = try requiredOutbox().prepare(body: body, points: points, visitCount: visits.count,
                                        for: request, history: history)
        refreshQueue()
        try await drainPrepared()
    }

    private func configuredRequest() throws -> URLRequest {
        guard let url = buildURL() else { throw WebhookError.invalidURL }
        if authType == .customHeader && ["x-whereday-export-format", "x-whereday-export-id", "x-whereday-export-sha256"].contains(authKey.lowercased()) {
            throw WebhookOutbox.QueueError.reservedAuthHeader
        }
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue(format.mimeType, forHTTPHeaderField: "Content-Type")
        // JSON, OwnTracks and Overland can share a MIME type. Bind their
        // distinct format tokens too, without storing a credential or endpoint.
        request.setValue(format.token, forHTTPHeaderField: "X-Whereday-Export-Format")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("Whereday/\(AppInfo.version)", forHTTPHeaderField: "User-Agent")
        applyAuth(to: &request)
        return request
    }

    private func validateCurrentSettings(_ request: URLRequest) throws {
        guard isEnabled else { throw WebhookOutbox.QueueError.disabled }
        guard try WebhookOutbox.binding(for: request) == WebhookOutbox.binding(for: configuredRequest()) else {
            throw WebhookOutbox.QueueError.changedDestination
        }
    }

    private func deliverPrepared(request configured: URLRequest, maximumAttempts: Int? = nil) async throws {
        guard !deliveryActive else { throw WebhookOutbox.QueueError.busy }
        deliveryActive = true
        isSending = true
        defer { deliveryActive = false; isSending = isDraining; refreshQueue() }
        let queue = try requiredOutbox()
        guard let original = try queue.read(for: configured).prepared else { return }
        let attempts = max(1, maximumAttempts ?? retryPolicy.maxAttempts)
        for attempt in 1...attempts {
            try Task.checkCancellation()
            try validateCurrentSettings(configured)
            var state = try queue.read(for: configured)
            guard var prepared = state.prepared, prepared.sha256 == original.sha256 else {
                throw WebhookOutbox.QueueError.unavailable
            }
            if attempt > 1 { await sleep(retryPolicy.delay(beforeAttempt: attempt)) }
            try Task.checkCancellation()
            try validateCurrentSettings(configured)
            do {
                // An uncertain POST never earns a blind replay. The receiver
                // must identify the exact digest under the same account-bound
                // export and explicitly permit an idempotent continuation.
                if prepared.attempted && prepared.receiverExportID == nil {
                    throw WebhookOutbox.QueueError.recoveryUnavailable
                }
                if let receipt = try await reconcile(configured, prepared: prepared,
                                                       allowUnsupported: !prepared.attempted) {
                    try validateCurrentSettings(configured)
                    prepared.receiverExportID = receipt.exportID
                    state = try queue.read(for: configured)
                    state.prepared = prepared
                    try queue.save(state)
                    if receipt.accepted {
                        complete(try queue.acknowledge(for: configured, digest: prepared.sha256, statusCode: 200))
                        return
                    }
                }
                try Task.checkCancellation()
                try validateCurrentSettings(configured)
                var request = configured
                request.httpBody = prepared.body
                request.setValue(prepared.receiverExportID, forHTTPHeaderField: "X-Whereday-Export-ID")
                prepared.attempted = true
                state = try queue.read(for: configured)
                state.prepared = prepared
                try queue.save(state) // Must be durable before the first byte leaves the app.
                let (data, response) = try await urlSession.data(for: request)
                guard let response = response as? HTTPURLResponse else { throw WebhookError.httpError(0) }
                if (200..<300).contains(response.statusCode) {
                    if let expected = prepared.receiverExportID {
                        guard data.count <= 8192,
                              let receipt = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                              receipt["status"] as? String == "accepted",
                              receipt["sha256"] as? String == prepared.sha256,
                              (receipt["capture"] as? [String: Any])?["export_id"] as? String == expected else {
                            throw WebhookOutbox.QueueError.recoveryUnavailable
                        }
                    }
                    // A settings edit while awaiting the response must not move
                    // the new account's cursor. Acknowledge only the saved binding.
                    complete(try queue.acknowledge(for: configured, digest: prepared.sha256,
                                                   statusCode: response.statusCode))
                    return
                }
                if response.statusCode == 503,
                   let progress = Self.membershipProgress(data, prepared: prepared) {
                    prepared.membership = progress
                    // Preserve points that may have been enqueued while awaiting HTTP.
                    state = try queue.read(for: configured)
                    state.prepared = prepared
                    try queue.save(state)
                }
                throw WebhookError.httpError(response.statusCode)
            } catch {
                let latest = try queue.read(for: configured).prepared
                guard attempt < attempts, latest?.receiverExportID != nil,
                      Self.shouldRetry(error), !Task.isCancelled else { throw error }
            }
        }
    }

    private func reconcile(_ original: URLRequest, prepared: WebhookOutbox.Prepared,
                           allowUnsupported: Bool) async throws -> (accepted: Bool, exportID: String)? {
        var request = original
        request.httpMethod = "GET"
        request.httpBody = nil
        request.setValue(nil, forHTTPHeaderField: "Content-Length")
        request.setValue(prepared.sha256, forHTTPHeaderField: "X-Whereday-Export-SHA256")
        request.cachePolicy = .reloadIgnoringLocalCacheData
        let (data, response) = try await urlSession.data(for: request)
        guard let response = response as? HTTPURLResponse else { throw WebhookOutbox.QueueError.recoveryUnavailable }
        if allowUnsupported && [404, 405, 501].contains(response.statusCode) { return nil }
        let receipt = data.count <= 8192 ? (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] : nil
        let status = receipt?["status"] as? String
        if allowUnsupported, response.statusCode == 200, !["accepted", "capture_pending"].contains(status ?? "") {
            return nil
        }
        guard response.statusCode == 200,
              receipt?["sha256"] as? String == prepared.sha256,
              let exportID = (receipt?["capture"] as? [String: Any])?["export_id"] as? String,
              !exportID.isEmpty, exportID.count <= 512,
              prepared.receiverExportID == nil || prepared.receiverExportID == exportID else {
            throw WebhookOutbox.QueueError.recoveryUnavailable
        }
        if status == "accepted" { return (true, exportID) }
        guard status == "capture_pending", receipt?["retry_same_original"] as? Bool == true else {
            throw WebhookOutbox.QueueError.recoveryUnavailable
        }
        return (false, exportID)
    }

    private static func membershipProgress(_ data: Data, prepared: WebhookOutbox.Prepared) -> WebhookOutbox.Membership? {
        guard data.count <= 8192,
              let value = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              value["status"] as? String == "capture_membership_pending",
              value["retry_same_original"] as? Bool == true,
              let exportID = value["export_id"] as? String, exportID == prepared.receiverExportID,
              let next = value["next_cursor"] as? Int, let total = value["total"] as? Int,
              next > (prepared.membership?.nextCursor ?? 0), next < total, total <= prepared.body.count,
              prepared.membership == nil || prepared.membership?.total == total else { return nil }
        return .init(exportID: exportID, nextCursor: next, total: total)
    }

    private func complete(_ state: WebhookOutbox.State) {
        lastSentAt = state.lastSentAt
        defaults.set(lastSentAt, forKey: Self.key(.lastSentAt))
        lastStatusCode = state.lastStatusCode
        defaults.set(lastStatusCode, forKey: Self.key(.lastStatusCode))
        lastError = nil
        defaults.removeObject(forKey: Self.key(.lastError))
        queuedPointCount = state.queuedPointCount
        LogManager.shared.info("Webhook delivery confirmed · \(Self.statusText(state.lastStatusCode ?? 200))", category: .webhook)
    }

    /// "200 OK", "204 No Content", or the bare code for anything less common.
    static func statusText(_ code: Int) -> String {
        let reasons: [Int: String] = [
            200: "OK", 201: "Created", 202: "Accepted", 204: "No Content",
            400: "Bad Request", 401: "Unauthorized", 403: "Forbidden", 404: "Not Found",
            408: "Request Timeout", 429: "Too Many Requests",
            500: "Internal Server Error", 502: "Bad Gateway", 503: "Service Unavailable", 504: "Gateway Timeout"
        ]
        guard let reason = reasons[code] else { return "\(code)" }
        return "\(code) \(reason)"
    }

    private static func shouldRetry(_ error: Error) -> Bool {
        if error is URLError {
            return true
        }

        guard let webhookError = error as? WebhookError else {
            return false
        }

        switch webhookError {
        case .httpError(let code):
            return code == 0 || code == 408 || code == 429 || code >= 500
        case .invalidURL, .unauthorized:
            return false
        }
    }

    // MARK: - URL building

    private func buildURL() -> URL? {
        guard !urlString.isEmpty else { return nil }
        var urlStr = urlString.trimmingCharacters(in: .whitespacesAndNewlines)

        if authType == .apiKeyQuery, !authKey.isEmpty, !authValue.isEmpty {
            let separator = urlStr.contains("?") ? "&" : "?"
            let encodedKey = authKey.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? authKey
            let encodedValue = authValue.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? authValue
            urlStr += "\(separator)\(encodedKey)=\(encodedValue)"
        }

        return URL(string: urlStr)
    }

    // MARK: - Auth

    private func applyAuth(to request: inout URLRequest) {
        switch authType {
        case .none, .apiKeyQuery:
            break
        case .bearer:
            if !authValue.isEmpty {
                request.setValue("Bearer \(authValue)", forHTTPHeaderField: "Authorization")
            }
        case .basic:
            if !authUsername.isEmpty || !authValue.isEmpty {
                let login = "\(authUsername):\(authValue)"
                if let encoded = login.data(using: .utf8)?.base64EncodedString() {
                    request.setValue("Basic \(encoded)", forHTTPHeaderField: "Authorization")
                }
            }
        case .customHeader:
            if !authKey.isEmpty, !authValue.isEmpty {
                request.setValue(authValue, forHTTPHeaderField: authKey)
            }
        }
    }

    // MARK: - Payload formatting

    private func formatPayload(points: [LocationPoint], visits: [Visit] = []) throws -> Data {
        let hasVisits = !visits.isEmpty
        switch format {
        case .owntracks:
            return try ExportService.exportLocationPointsToOwnTracks(points: points)
        case .overland:
            return try ExportService.exportLocationPointsToOverland(points: points)
        case .json:
            if hasVisits {
                return try ExportService.exportCombinedToJSON(visits: visits, points: points)
            }
            return try ExportService.exportLocationPointsToJSON(points: points)
        case .csv:
            if hasVisits {
                return ExportService.exportCombinedToCSV(visits: visits, points: points)
            }
            return ExportService.exportLocationPointsToCSV(points: points)
        case .markdown:
            if hasVisits {
                return ExportService.exportCombinedToMarkdown(visits: visits, points: points)
            }
            return ExportService.exportLocationPointsToMarkdown(points: points)
        case .gpx:
            if hasVisits {
                return ExportService.exportCombinedToGPX(visits: visits, points: points)
            }
            return ExportService.exportLocationPointsToGPX(points: points)
        case .kml:
            if hasVisits {
                return ExportService.exportCombinedToKML(visits: visits, points: points)
            }
            return ExportService.exportLocationPointsToKML(points: points)
        case .geojson:
            if hasVisits {
                return try ExportService.exportCombinedToGeoJSON(visits: visits, points: points)
            }
            return try ExportService.exportLocationPointsToGeoJSON(points: points)
        }
    }

    // MARK: - Helpers

    static func sanitizeError(_ message: String, masking secret: String) -> String {
        guard !secret.isEmpty else { return message }
        return message.replacingOccurrences(of: secret, with: "***")
    }

    private func recordError(_ message: String) {
        let sanitized = Self.sanitizeError(message, masking: authValue)
        lastError = sanitized
        defaults.set(sanitized, forKey: Self.key(.lastError))
        LogManager.shared.error(sanitized, category: .webhook)
    }

    static func formatFromToken(_ token: String?) -> ExportFormat {
        switch token {
        case "csv": return .csv
        case "md", "markdown": return .markdown
        case "owntracks": return .owntracks
        case "overland": return .overland
        case "gpx": return .gpx
        case "kml": return .kml
        case "geojson": return .geojson
        default: return .json
        }
    }

    // MARK: - Keychain

    static func keychainReadString(account: String) -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess,
              let data = result as? Data,
              let string = String(data: data, encoding: .utf8) else {
            return nil
        }
        return string
    }

    static func keychainWriteString(_ value: String, account: String) {
        if value.isEmpty {
            let deleteQuery: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrAccount as String: account,
            ]
            SecItemDelete(deleteQuery as CFDictionary)
            return
        }

        guard let data = value.data(using: .utf8) else { return }
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: account,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlock,
        ]
        let updateAttributes: [String: Any] = [kSecValueData as String: data]
        let status = SecItemUpdate(query as CFDictionary, updateAttributes as CFDictionary)
        if status == errSecItemNotFound {
            var addQuery = query
            addQuery[kSecValueData as String] = data
            SecItemAdd(addQuery as CFDictionary, nil)
        }
    }
}

// MARK: - Errors

enum WebhookError: LocalizedError {
    case invalidURL
    case httpError(Int)
    case unauthorized

    var errorDescription: String? {
        switch self {
        case .invalidURL:
            return String(localized: "Invalid URL")
        case .httpError(let code):
            return String(localized: "Server returned HTTP \(code)")
        case .unauthorized:
            return String(localized: "Unauthorized (HTTP 401). Check your credentials.")
        }
    }
}

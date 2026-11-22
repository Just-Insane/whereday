import CryptoKit
import Foundation

/// App-owned custody for webhook work. One atomic file binds pending points,
/// exact prepared bytes and the acknowledged cursor to the current destination
/// and authorization. Credentials are hashed transiently, never stored here.
@MainActor
final class WebhookOutbox {
    static let maximumBodyBytes = 16 * 1024 * 1024
    private static let maximumStateBytes = 64 * 1024 * 1024

    struct Point: Codable {
        let id: UUID
        let latitude: Double
        let longitude: Double
        let timestamp: Date
        let altitude: Double?
        let speed: Double?
        let horizontalAccuracy: Double
        let isOutlier: Bool

        init(_ point: LocationPoint) {
            id = point.id; latitude = point.latitude; longitude = point.longitude
            timestamp = point.timestamp; altitude = point.altitude; speed = point.speed
            horizontalAccuracy = point.horizontalAccuracy; isOutlier = point.isOutlier
        }

        func model() -> LocationPoint {
            LocationPoint(id: id, latitude: latitude, longitude: longitude,
                          timestamp: timestamp, altitude: altitude, speed: speed,
                          horizontalAccuracy: horizontalAccuracy, isOutlier: isOutlier)
        }
    }

    struct Cursor: Codable, Equatable {
        var timestamp: Date
        var pointIDs: Set<UUID>

        func includes(_ point: LocationPoint) -> Bool {
            point.timestamp < timestamp || (point.timestamp == timestamp && pointIDs.contains(point.id))
        }

        mutating func advance(through points: [Point]) {
            guard let newest = points.map(\.timestamp).max(), newest >= timestamp else { return }
            let ids = Set(points.filter { $0.timestamp == newest }.map(\.id))
            if newest == timestamp { pointIDs.formUnion(ids) }
            else { timestamp = newest; pointIDs = ids }
        }
    }

    struct Membership: Codable, Equatable {
        let exportID: String
        let nextCursor: Int
        let total: Int
    }

    struct Prepared: Codable {
        let body: Data
        let sha256: String
        let points: [Point]
        let visitCount: Int
        var attempted = false
        var receiverExportID: String?
        var membership: Membership?
    }

    struct State: Codable {
        var version = 1
        let binding: String
        var pending: [Point] = []
        var cursor: Cursor?
        var prepared: Prepared?
        var lastSentAt: Date?
        var lastStatusCode: Int?

        var queuedPointCount: Int {
            Set(pending.map(\.id) + (prepared?.points.map(\.id) ?? [])).count
        }
    }

    enum QueueError: LocalizedError {
        case unavailable, changedDestination, recoveryUnavailable, busy, tooLarge, disabled, unsupportedVisits
        var errorDescription: String? {
            switch self {
            case .unavailable:
                return "The protected webhook queue is unavailable. Saved work has not been discarded."
            case .changedDestination:
                return "Webhook settings changed. The prepared delivery remains with its original destination and credentials."
            case .recoveryUnavailable:
                return "The endpoint could not confirm a previous delivery. Its original bytes remain queued; no uncertain upload was repeated."
            case .busy:
                return "A webhook delivery is already in progress."
            case .tooLarge:
                return "The complete webhook export exceeds 16 MiB. It was not sent or truncated. Use a smaller point batch."
            case .disabled:
                return "Webhook delivery is disabled. Pending work remains saved."
            case .unsupportedVisits:
                return "This format supports location points only. Choose JSON, CSV, Markdown, GPX, KML or GeoJSON to send visits."
            }
        }
    }

    private let directory: URL
    private let files: FileManager

    init(directory: URL? = nil, fileManager: FileManager = .default) throws {
        files = fileManager
        self.directory = try directory ?? fileManager.url(
            for: .applicationSupportDirectory, in: .userDomainMask,
            appropriateFor: nil, create: true
        ).appendingPathComponent("WebhookOutbox", isDirectory: true)
        try files.createDirectory(at: self.directory, withIntermediateDirectories: true,
                                  attributes: [.posixPermissions: 0o700])
        #if os(iOS)
        try files.setAttributes([.protectionKey: FileProtectionType.completeUntilFirstUserAuthentication],
                                ofItemAtPath: self.directory.path)
        #endif
        var location = self.directory
        var resources = URLResourceValues()
        resources.isExcludedFromBackup = true
        try location.setResourceValues(resources)
    }

    static func digest(_ bytes: Data) -> String {
        SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
    }

    static func binding(for request: URLRequest) throws -> String {
        guard let url = request.url else { throw QueueError.changedDestination }
        // Include custom auth headers and query credentials as well as Bearer
        // authorization. Sort/lowercase header names without saving their values.
        let headers = (request.allHTTPHeaderFields ?? [:])
            .filter { !["user-agent", "content-length"].contains($0.key.lowercased()) }
            .map { [$0.key.lowercased(), $0.value] }.sorted { $0[0] < $1[0] }
        return digest(try JSONEncoder().encode([[url.absoluteString, request.httpMethod ?? "POST"]] + headers))
    }

    func read(for request: URLRequest) throws -> State {
        let binding = try Self.binding(for: request), url = stateURL(binding)
        guard files.fileExists(atPath: url.path) else { return State(binding: binding) }
        let data = try Data(contentsOf: url)
        guard data.count <= Self.maximumStateBytes else { throw QueueError.unavailable }
        let state = try JSONDecoder().decode(State.self, from: data)
        guard state.version == 1, state.binding == binding,
              Set(state.pending.map(\.id)).count == state.pending.count,
              state.lastStatusCode == nil || (200..<300).contains(state.lastStatusCode!) else {
            throw QueueError.unavailable
        }
        if let prepared = state.prepared {
            guard !prepared.body.isEmpty, prepared.body.count <= Self.maximumBodyBytes,
                  Self.digest(prepared.body) == prepared.sha256,
                  Set(prepared.points.map(\.id)).count == prepared.points.count,
                  prepared.visitCount >= 0,
                  !prepared.points.isEmpty || prepared.visitCount > 0 else { throw QueueError.unavailable }
        }
        return state
    }

    func save(_ state: State) throws {
        guard state.binding.range(of: #"^[a-f0-9]{64}$"#, options: .regularExpression) != nil else {
            throw QueueError.unavailable
        }
        let encoded = try JSONEncoder().encode(state)
        guard encoded.count <= Self.maximumStateBytes else { throw QueueError.unavailable }
        let url = stateURL(state.binding)
        #if os(iOS)
        try encoded.write(to: url, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
        #else
        try encoded.write(to: url, options: .atomic)
        #endif
        try files.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
        let handle = try FileHandle(forWritingTo: url)
        defer { try? handle.close() }
        try handle.synchronize()
    }

    func enqueue(_ points: [LocationPoint], for request: URLRequest) throws -> State {
        var state = try read(for: request)
        var known = Set(state.pending.map(\.id) + (state.prepared?.points.map(\.id) ?? []))
        for point in points where known.insert(point.id).inserted {
            state.pending.append(Point(point))
        }
        try save(state)
        return state
    }

    func prepare(body: Data, points: [LocationPoint], visitCount: Int, for request: URLRequest) throws -> State {
        guard body.count <= Self.maximumBodyBytes else { throw QueueError.tooLarge }
        var state = try read(for: request)
        guard state.prepared == nil else { throw QueueError.busy }
        state.prepared = Prepared(body: body, sha256: Self.digest(body), points: points.map(Point.init), visitCount: visitCount)
        try save(state)
        return state
    }

    /// One durable replacement commits both the receipt/cursor and queue
    /// removal. A crash cannot expose a cleared queue with an old cursor.
    func acknowledge(for request: URLRequest, digest: String, statusCode: Int) throws -> State {
        var state = try read(for: request)
        guard let prepared = state.prepared, prepared.sha256 == digest,
              (200..<300).contains(statusCode) else { throw QueueError.unavailable }
        let sent = Set(prepared.points.map(\.id))
        state.pending.removeAll { sent.contains($0.id) }
        if state.cursor == nil, let first = prepared.points.map(\.timestamp).min() {
            state.cursor = Cursor(timestamp: first, pointIDs: [])
        }
        state.cursor?.advance(through: prepared.points)
        state.lastSentAt = Date(); state.lastStatusCode = statusCode
        state.prepared = nil
        try save(state)
        return state
    }

    func clearWaiting(for request: URLRequest) throws -> State {
        var state = try read(for: request)
        // An unknown delivery is evidence, not an unsent draft. Keep the queue
        // intact until it is reconciled; its cursor cannot safely be skipped.
        if let prepared = state.prepared, prepared.attempted {
            return state
        } else {
            let discarded = state.pending + (state.prepared?.points ?? [])
            if state.cursor == nil, let first = discarded.map(\.timestamp).min() {
                state.cursor = Cursor(timestamp: first, pointIDs: [])
            }
            state.cursor?.advance(through: discarded)
            state.pending.removeAll()
            state.prepared = nil
        }
        try save(state)
        return state
    }

    private func stateURL(_ binding: String) -> URL { directory.appendingPathComponent(binding + ".json") }
}

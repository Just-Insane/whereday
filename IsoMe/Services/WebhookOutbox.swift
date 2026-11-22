import CryptoKit
import Foundation

/// App-owned custody for webhook work. One atomic file binds pending points,
/// exact prepared bytes and the acknowledged cursor to the current destination
/// and authorization. Credentials are hashed transiently, never stored here.
@MainActor
final class WebhookOutbox {
    nonisolated static let maximumBodyBytes = 16 * 1024 * 1024
    nonisolated private static let maximumStateBytes = 64 * 1024 * 1024

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
        var sourceTime: Date?
        var history: Bool?
    }

    /// Bodies are separate from operation metadata: a history selection has no
    /// total queue-size ceiling and receipt updates never rewrite other originals.
    private struct Stored: Codable {
        var sha256: String
        var points: [Point]
        var visitCount: Int
        var attempted: Bool
        var receiverExportID: String?
        var membership: Membership?
        var sourceTime: Date?
        var history: Bool?
        var settledAt: Date?
        var statusCode: Int?

        init(_ prepared: Prepared) {
            sha256 = prepared.sha256; points = prepared.points; visitCount = prepared.visitCount
            attempted = prepared.attempted; receiverExportID = prepared.receiverExportID
            membership = prepared.membership; sourceTime = prepared.sourceTime; history = prepared.history
        }

        func prepared(body: Data) -> Prepared {
            Prepared(body: body, sha256: sha256, points: points, visitCount: visitCount,
                     attempted: attempted, receiverExportID: receiverExportID, membership: membership,
                     sourceTime: sourceTime, history: history)
        }
    }

    struct Chunk {
        let body: Data
        let pointIndices: [Int]
        let visitCount: Int
        let sourceTime: Date?
    }

    struct State: Codable {
        var version = 1
        let binding: String
        var pending: [Point] = []
        var cursor: Cursor?
        var prepared: Prepared?
        var lastSentAt: Date?
        var lastStatusCode: Int?
        var otherQueuedPointCount = 0

        private enum CodingKeys: String, CodingKey {
            case version, binding, pending, cursor, prepared, lastSentAt, lastStatusCode
        }

        var queuedPointCount: Int {
            Set(pending.map(\.id) + (prepared?.points.map(\.id) ?? [])).count + otherQueuedPointCount
        }
    }

    enum QueueError: LocalizedError {
        case unavailable, changedDestination, recoveryUnavailable, busy, tooLarge, disabled, unsupportedVisits, reservedAuthHeader
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
                return "One complete webhook record exceeds 16 MiB, or this format cannot be split. It remains unsent. Use JSON for full history."
            case .disabled:
                return "Webhook delivery is disabled. Pending work remains saved."
            case .unsupportedVisits:
                return "This format supports location points only. Choose JSON, CSV, Markdown, GPX, KML or GeoJSON to send visits."
            case .reservedAuthHeader:
                return "Choose a different custom authentication header. X-Whereday-Export-Format, X-Whereday-Export-ID and X-Whereday-Export-SHA256 are reserved for delivery identity."
            }
        }
    }

    private let directory: URL
    private let files: FileManager
    private let maximumPayloadBytes: Int

    init(directory: URL? = nil, fileManager: FileManager = .default,
         maximumPayloadBytes: Int = WebhookOutbox.maximumBodyBytes) throws {
        files = fileManager
        self.maximumPayloadBytes = min(Self.maximumBodyBytes, maximumPayloadBytes)
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
        let data = files.fileExists(atPath: url.path)
            ? try Data(contentsOf: url) : try JSONEncoder().encode(State(binding: binding))
        guard data.count <= Self.maximumStateBytes else { throw QueueError.unavailable }
        var state = try JSONDecoder().decode(State.self, from: data)
        guard state.version == 1, state.binding == binding,
              Set(state.pending.map(\.id)).count == state.pending.count,
              state.lastStatusCode == nil || (200..<300).contains(state.lastStatusCode!) else {
            throw QueueError.unavailable
        }
        if let prepared = state.prepared {
            try validate(prepared)
            if let url = try operationURL(prepared.sha256, binding: binding) {
                let stored = try readStored(url)
                if let settled = stored.settledAt {
                    settle(&state, points: stored.points, at: settled, statusCode: stored.statusCode)
                    state.prepared = nil
                } else {
                    // Metadata is saved before an HTTP attempt and before the
                    // state projection. Recover the newer receipt after a crash.
                    state.prepared = stored.prepared(body: prepared.body)
                }
            }
        }
        let covered = Set(state.pending.map(\.id) + (state.prepared?.points.map(\.id) ?? []))
        let others = Set(try operations(binding: binding).filter { $0.1.settledAt == nil }.flatMap { $0.1.points.map(\.id) })
        state.otherQueuedPointCount = others.subtracting(covered).count
        return state
    }

    private func validate(_ prepared: Prepared) throws {
        guard !prepared.body.isEmpty, prepared.body.count <= Self.maximumBodyBytes,
              Self.digest(prepared.body) == prepared.sha256,
              Set(prepared.points.map(\.id)).count == prepared.points.count,
              prepared.visitCount >= 0,
              !prepared.points.isEmpty || prepared.visitCount > 0 else { throw QueueError.unavailable }
    }

    private func write(_ bytes: Data, to url: URL) throws {
        #if os(iOS)
        try bytes.write(to: url, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
        #else
        try bytes.write(to: url, options: .atomic)
        #endif
        try files.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
        let handle = try FileHandle(forWritingTo: url)
        defer { try? handle.close() }
        try handle.synchronize()
    }

    func save(_ state: State) throws {
        guard state.binding.range(of: #"^[a-f0-9]{64}$"#, options: .regularExpression) != nil else {
            throw QueueError.unavailable
        }
        // The independent operation is authoritative. Never acknowledge, park
        // or replace another operation merely to make room for this one.
        if let prepared = state.prepared {
            try validate(prepared)
            if let url = try operationURL(prepared.sha256, binding: state.binding) {
                guard try readStored(url).settledAt == nil else { throw QueueError.unavailable }
                try write(try JSONEncoder().encode(Stored(prepared)), to: url)
            } else {
                try storeBatch([prepared], binding: state.binding)
            }
        }
        let encoded = try JSONEncoder().encode(state)
        guard encoded.count <= Self.maximumStateBytes else { throw QueueError.unavailable }
        try write(encoded, to: stateURL(state.binding))
    }

    func enqueue(_ points: [LocationPoint], for request: URLRequest) throws -> State {
        var state = try read(for: request)
        var known = Set(state.pending.map(\.id) + (state.prepared?.points.map(\.id) ?? []))
        for (_, stored) in try operations(binding: state.binding) {
            known.formUnion(stored.points.map(\.id))
        }
        for point in points where known.insert(point.id).inserted {
            state.pending.append(Point(point))
        }
        try save(state)
        return state
    }

    /// These source records have durable custody but no prepared original yet.
    /// Already prepared history never needs to be reformatted to admit fresh work.
    func unpreparedPoints(for request: URLRequest) throws -> [LocationPoint] {
        let state = try read(for: request)
        var prepared = Set(state.prepared?.points.map(\.id) ?? [])
        for (_, stored) in try operations(binding: state.binding) { prepared.formUnion(stored.points.map(\.id)) }
        return state.pending.filter { !prepared.contains($0.id) }
            .sorted { $0.timestamp > $1.timestamp }.map { $0.model() }
    }

    func prepare(body: Data, points: [LocationPoint], visitCount: Int, for request: URLRequest,
                 history: Bool = false) throws -> State {
        var state = try read(for: request)
        // ExportService emits location points in ascending timestamp order.
        let sortedPoints = points.sorted { $0.timestamp < $1.timestamp }
        let chunks = try Self.boundedPayloads(body, pointCount: points.count, visitCount: visitCount,
                                             maximumBytes: maximumPayloadBytes)
        let originals = chunks.map { chunk in
            Prepared(body: chunk.body, sha256: Self.digest(chunk.body),
                     points: chunk.pointIndices.map { Point(sortedPoints[$0]) }, visitCount: chunk.visitCount,
                     sourceTime: chunk.sourceTime ?? points.map(\.timestamp).max(), history: history)
        }
        // Hash identity must not silently collapse distinct chunks that happen
        // to have indistinguishable native representations.
        guard Set(originals.map(\.sha256)).count == originals.count else { throw QueueError.unavailable }
        try storeBatch(originals, binding: state.binding)
        if state.prepared == nil { state.prepared = originals.first }
        try save(state)
        return state
    }

    func hasHistory(for request: URLRequest) throws -> Bool {
        let state = try read(for: request)
        if let prepared = state.prepared,
           prepared.history == true || (prepared.history == nil && prepared.attempted) { return true }
        return try operations(binding: state.binding).contains {
            $0.1.settledAt == nil && $0.1.history == true
        }
    }

    /// Select between independent operations after every HTTP result. The
    /// caller excludes operations already visited in this round, including an
    /// unresolved historical request, so each source has a bounded opportunity.
    func nextDigest(for request: URLRequest, excluding: Set<String>) throws -> String? {
        let state = try read(for: request)
        var pending = try operations(binding: state.binding).map(\.1)
            .filter { $0.settledAt == nil && !excluding.contains($0.sha256) }
        if let prepared = state.prepared, !excluding.contains(prepared.sha256),
           !pending.contains(where: { $0.sha256 == prepared.sha256 }) { pending.append(Stored(prepared)) }
        return pending.sorted {
            let a = $0.sourceTime ?? $0.points.map(\.timestamp).max() ?? .distantPast
            let b = $1.sourceTime ?? $1.points.map(\.timestamp).max() ?? .distantPast
            if a != b { return a > b }
            return $0.sha256 < $1.sha256
        }.first?.sha256
    }

    func activate(_ digest: String, for request: URLRequest) throws {
        var state = try read(for: request)
        // Persist a legacy in-state request before switching its projection.
        if let previous = state.prepared { try storeBatch([previous], binding: state.binding) }
        guard let url = try operationURL(digest, binding: state.binding) else { throw QueueError.unavailable }
        let stored = try readStored(url)
        guard stored.settledAt == nil else { throw QueueError.unavailable }
        let body = try Data(contentsOf: url.deletingPathExtension().appendingPathExtension("body"))
        let prepared = stored.prepared(body: body)
        try validate(prepared)
        state.prepared = prepared
        try save(state)
    }

    func acknowledge(for request: URLRequest, digest: String, statusCode: Int) throws -> State {
        var state = try read(for: request)
        guard let prepared = state.prepared, prepared.sha256 == digest,
              (200..<300).contains(statusCode) else { throw QueueError.unavailable }
        try storeBatch([prepared], binding: state.binding)
        guard let url = try operationURL(digest, binding: state.binding) else { throw QueueError.unavailable }
        var stored = try readStored(url)
        stored.settledAt = Date(); stored.statusCode = statusCode
        // A receipt survives a crash before cursor advancement or body cleanup.
        // The same operation can never become an unattempted draft again.
        try write(try JSONEncoder().encode(stored), to: url)
        settle(&state, points: prepared.points, at: stored.settledAt!, statusCode: statusCode)
        state.prepared = nil
        try save(state)
        try? files.removeItem(at: url.deletingPathExtension().appendingPathExtension("body"))
        return state
    }

    private func settle(_ state: inout State, points: [Point], at date: Date, statusCode: Int?) {
        let sent = Set(points.map(\.id))
        state.pending.removeAll { sent.contains($0.id) }
        if state.cursor == nil, let first = points.map(\.timestamp).min() {
            state.cursor = Cursor(timestamp: first, pointIDs: [])
        }
        state.cursor?.advance(through: points)
        if let statusCode { state.lastSentAt = date; state.lastStatusCode = statusCode }
    }

    func clearWaiting(for request: URLRequest) throws -> State {
        var state = try read(for: request)
        if let prepared = state.prepared { try storeBatch([prepared], binding: state.binding) }
        var retained = Set<UUID>()
        for (url, var stored) in try operations(binding: state.binding) where stored.settledAt == nil {
            if stored.attempted { retained.formUnion(stored.points.map(\.id)); continue }
            stored.settledAt = Date()
            try write(try JSONEncoder().encode(stored), to: url)
            settle(&state, points: stored.points, at: stored.settledAt!, statusCode: nil)
            try? files.removeItem(at: url.deletingPathExtension().appendingPathExtension("body"))
        }
        let discarded = state.pending.filter { !retained.contains($0.id) }
        settle(&state, points: discarded, at: Date(), statusCode: nil)
        if state.prepared?.attempted != true { state.prepared = nil }
        try save(state)
        return state
    }

    private func readStored(_ url: URL) throws -> Stored {
        let data = try Data(contentsOf: url)
        guard data.count <= Self.maximumStateBytes else { throw QueueError.unavailable }
        let stored = try JSONDecoder().decode(Stored.self, from: data)
        guard stored.sha256.range(of: #"^[a-f0-9]{64}$"#, options: .regularExpression) != nil,
              url.deletingPathExtension().lastPathComponent == stored.sha256,
              Set(stored.points.map(\.id)).count == stored.points.count,
              stored.visitCount >= 0, !stored.points.isEmpty || stored.visitCount > 0 else {
            throw QueueError.unavailable
        }
        return stored
    }

    private func operationFiles(binding: String) throws -> [URL] {
        let root = directory.appendingPathComponent(binding, isDirectory: true)
        guard files.fileExists(atPath: root.path) else { return [] }
        return try files.contentsOfDirectory(at: root, includingPropertiesForKeys: nil)
            .filter { $0.lastPathComponent.hasPrefix("batch-") }.flatMap {
                try files.contentsOfDirectory(at: $0, includingPropertiesForKeys: nil).filter { $0.pathExtension == "json" }
            }
    }

    private func operations(binding: String) throws -> [(URL, Stored)] {
        // Unknown identity metadata must not turn an attempted original back
        // into a draft. Preserve the queue and surface that integrity failure.
        try operationFiles(binding: binding).map { ($0, try readStored($0)) }
    }

    func damagedOperationCount(for request: URLRequest) throws -> Int {
        let paths = try operationFiles(binding: Self.binding(for: request))
        return paths.filter { (try? readStored($0)) == nil }.count
    }

    private func operationURL(_ digest: String, binding: String) throws -> URL? {
        try operationFiles(binding: binding).first { $0.deletingPathExtension().lastPathComponent == digest }
    }

    private func storeBatch(_ originals: [Prepared], binding: String) throws {
        let existing = Set(try operationFiles(binding: binding).map { $0.deletingPathExtension().lastPathComponent })
        let new = originals.filter { !existing.contains($0.sha256) }
        guard !new.isEmpty else { return }
        let root = directory.appendingPathComponent(binding, isDirectory: true)
        try files.createDirectory(at: root, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let suffix = UUID().uuidString
        let staging = root.appendingPathComponent(".staging-" + suffix, isDirectory: true)
        try files.createDirectory(at: staging, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        for prepared in new {
            try validate(prepared)
            try write(prepared.body, to: staging.appendingPathComponent(prepared.sha256 + ".body"))
            try write(try JSONEncoder().encode(Stored(prepared)), to: staging.appendingPathComponent(prepared.sha256 + ".json"))
        }
        // Every chunk of the snapshot has durable exact bytes before it becomes
        // selectable. An interrupted staging directory is never a submitted op.
        try files.moveItem(at: staging, to: root.appendingPathComponent("batch-" + suffix))
    }

    /// Complete native elements remain intact; only the surrounding ordinary
    /// export envelope and its local counts change. No partial-record protocol.
    static func boundedPayloads(_ body: Data, pointCount: Int, visitCount: Int,
                                maximumBytes: Int = maximumBodyBytes) throws -> [Chunk] {
        guard maximumBytes > 0 else { throw QueueError.tooLarge }
        if body.count <= maximumBytes {
            let object = (try? JSONSerialization.jsonObject(with: body)) as? [String: Any]
            let values = (object?["points"] as? [[String: Any]] ?? []) + (object?["visits"] as? [[String: Any]] ?? [])
            return [Chunk(body: body, pointIndices: Array(0..<pointCount), visitCount: visitCount,
                          sourceTime: values.map(sourceTime).max())]
        }
        guard let original = try JSONSerialization.jsonObject(with: body) as? [String: Any],
              original["exportDate"] is String else { throw QueueError.tooLarge }
        let points = original["points"] as? [[String: Any]] ?? []
        let visits = original["visits"] as? [[String: Any]] ?? []
        guard points.count == pointCount, visits.count == visitCount,
              !points.isEmpty || !visits.isEmpty else { throw QueueError.tooLarge }
        var items = points.enumerated().map { (visit: false, index: $0.offset, value: $0.element) } +
                    visits.enumerated().map { (visit: true, index: $0.offset, value: $0.element) }
        items.sort {
            let a = sourceTime($0.value), b = sourceTime($1.value)
            if a != b { return a > b }
            if $0.visit != $1.visit { return !$0.visit }
            return $0.index < $1.index
        }
        func partition(_ range: Range<Int>) throws -> [Chunk] {
            var envelope = original
            let selected = items[range]
            let pointItems = selected.filter { !$0.visit }
            let visitItems = selected.filter(\.visit)
            if original["points"] != nil { envelope["points"] = pointItems.map(\.value); envelope["totalPoints"] = pointItems.count }
            if original["visits"] != nil { envelope["visits"] = visitItems.map(\.value); envelope["totalVisits"] = visitItems.count }
            let bytes = try JSONSerialization.data(withJSONObject: envelope, options: [.sortedKeys])
            if bytes.count <= maximumBytes {
                return [Chunk(body: bytes, pointIndices: pointItems.map(\.index), visitCount: visitItems.count,
                              sourceTime: selected.map { sourceTime($0.value) }.max())]
            }
            guard range.count > 1 else { throw QueueError.tooLarge }
            let middle = range.lowerBound + range.count / 2
            return try partition(range.lowerBound..<middle) + partition(middle..<range.upperBound)
        }
        return try partition(0..<items.count)
    }

    private static func sourceTime(_ item: [String: Any]) -> Date {
        if let value = item["timestampUnix"] as? Double { return Date(timeIntervalSince1970: value) }
        let text = item["timestamp"] as? String ?? item["arrivalDate"] as? String ?? item["arrivedAt"] as? String ?? ""
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let date = formatter.date(from: text) { return date }
        formatter.formatOptions = [.withInternetDateTime]
        return formatter.date(from: text) ?? .distantPast
    }

    private func stateURL(_ binding: String) -> URL { directory.appendingPathComponent(binding + ".json") }
}

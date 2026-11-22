import Foundation

/// Splits native JSON exports into independently valid ordinary envelopes.
/// The caller owns durable preparation, point identity and receiver receipts.
enum WebhookJSONPartitioner {
    struct Chunk {
        let body: Data
        let pointIndices: [Int]
        let visitIndices: [Int]
        let visitCount: Int
        let sourceTime: Date?
    }

    enum PartitionError: Error, Equatable {
        case tooLarge
        case invalidEnvelope
    }

    private struct Item {
        let isVisit: Bool
        let index: Int
        let value: [String: Any]
        let sourceTime: Date?
    }

    /// Already bounded bodies retain their exact bytes, including other export
    /// formats. Only an oversized native JSON envelope can be partitioned.
    static func boundedPayloads(_ body: Data, pointCount: Int, visitCount: Int,
                                maximumBytes: Int = 16 * 1024 * 1024) throws -> [Chunk] {
        guard maximumBytes > 0 else { throw PartitionError.tooLarge }
        guard !body.isEmpty, pointCount >= 0, visitCount >= 0 else {
            throw PartitionError.invalidEnvelope
        }
        if body.count <= maximumBytes {
            let object = (try? JSONSerialization.jsonObject(with: body)) as? [String: Any]
            let values = (object?["points"] as? [[String: Any]] ?? []) +
                         (object?["visits"] as? [[String: Any]] ?? [])
            return [Chunk(body: body, pointIndices: Array(0..<pointCount),
                          visitIndices: Array(0..<visitCount), visitCount: visitCount,
                          sourceTime: values.compactMap { sourceTime($0) }.max())]
        }

        guard let original = (try? JSONSerialization.jsonObject(with: body)) as? [String: Any],
              original["exportDate"] is String,
              original["points"] != nil || original["visits"] != nil else {
            throw PartitionError.invalidEnvelope
        }
        func records(_ key: String, expected: Int) throws -> [[String: Any]] {
            guard let value = original[key] else {
                guard expected == 0 else { throw PartitionError.invalidEnvelope }
                return []
            }
            guard let values = value as? [[String: Any]], values.count == expected else {
                throw PartitionError.invalidEnvelope
            }
            return values
        }
        let points = try records("points", expected: pointCount)
        let visits = try records("visits", expected: visitCount)
        var items = points.enumerated().map {
            Item(isVisit: false, index: $0.offset, value: $0.element, sourceTime: sourceTime($0.element))
        } + visits.enumerated().map {
            Item(isVisit: true, index: $0.offset, value: $0.element, sourceTime: sourceTime($0.element))
        }
        // There is no record boundary at which oversized metadata alone can split.
        guard !items.isEmpty else { throw PartitionError.tooLarge }
        items.sort {
            let left = $0.sourceTime ?? .distantPast, right = $1.sourceTime ?? .distantPast
            if left != right { return left > right }
            if $0.isVisit != $1.isVisit { return !$0.isVisit }
            return $0.index < $1.index
        }

        func partition(_ range: Range<Int>) throws -> [Chunk] {
            let selected = items[range]
            // Keep each native array's relative order within an envelope. The
            // source indices still refer to the original, unsplit native arrays.
            let pointItems = selected.filter { !$0.isVisit }.sorted { $0.index < $1.index }
            let visitItems = selected.filter { $0.isVisit }.sorted { $0.index < $1.index }
            var envelope = original
            if original["points"] != nil {
                envelope["points"] = pointItems.map { $0.value }
                envelope["totalPoints"] = pointItems.count
            }
            if original["visits"] != nil {
                envelope["visits"] = visitItems.map { $0.value }
                envelope["totalVisits"] = visitItems.count
            }
            // Copying the full envelope and whole record dictionaries preserves
            // exportDate and every other known or unknown JSON field value.
            let bytes = try JSONSerialization.data(withJSONObject: envelope, options: [.sortedKeys])
            if bytes.count <= maximumBytes {
                return [Chunk(body: bytes, pointIndices: pointItems.map { $0.index },
                              visitIndices: visitItems.map { $0.index },
                              visitCount: visitItems.count,
                              sourceTime: selected.compactMap { $0.sourceTime }.max())]
            }
            guard range.count > 1 else { throw PartitionError.tooLarge }
            let middle = range.lowerBound + range.count / 2
            return try partition(range.lowerBound..<middle) + partition(middle..<range.upperBound)
        }
        return try partition(0..<items.count)
    }

    private static func sourceTime(_ item: [String: Any]) -> Date? {
        if let value = item["timestampUnix"] as? Double, value.isFinite {
            return Date(timeIntervalSince1970: value)
        }
        guard let text = item["timestamp"] as? String ?? item["arrivalDate"] as? String ??
                         item["arrivedAt"] as? String else { return nil }
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let date = formatter.date(from: text) { return date }
        formatter.formatOptions = [.withInternetDateTime]
        return formatter.date(from: text)
    }
}

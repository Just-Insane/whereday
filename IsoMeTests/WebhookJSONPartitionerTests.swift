import Foundation
import XCTest
@testable import IsoMe

final class WebhookJSONPartitionerTests: XCTestCase {
    private let exportDate = "2026-11-22T12:00:00.123Z"

    private func envelope(points: [[String: Any]], visits: [[String: Any]],
                          extra: [String: Any] = [:]) -> [String: Any] {
        var value = extra
        value["exportDate"] = exportDate
        value["totalPoints"] = points.count
        value["points"] = points
        value["totalVisits"] = visits.count
        value["visits"] = visits
        return value
    }

    private func encode(_ value: [String: Any]) throws -> Data {
        try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys])
    }

    private func decode(_ body: Data) throws -> [String: Any] {
        try XCTUnwrap(JSONSerialization.jsonObject(with: body) as? [String: Any])
    }

    private func ordered(_ records: [[String: Any]]) -> NSArray {
        records.sorted { ($0["nativeID"] as! String) < ($1["nativeID"] as! String) } as NSArray
    }

    private func assertError(_ expected: WebhookJSONPartitioner.PartitionError, body: Data,
                             pointCount: Int, visitCount: Int, maximumBytes: Int,
                             file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertThrowsError(try WebhookJSONPartitioner.boundedPayloads(
            body, pointCount: pointCount, visitCount: visitCount, maximumBytes: maximumBytes
        ), file: file, line: line) { error in
            XCTAssertEqual(error as? WebhookJSONPartitioner.PartitionError, expected, file: file, line: line)
        }
    }

    func testBoundedBodyRetainsItsExactBytesAtTheInclusiveLimit() throws {
        let body = Data("""
        { "exportDate" : "2026-11-22T12:00:00.123Z", "totalPoints" : 1,
          "points" : [ { "timestampUnix" : 1700000000, "unknown" : "🧭" } ] }
        """.utf8)
        let chunks = try WebhookJSONPartitioner.boundedPayloads(
            body, pointCount: 1, visitCount: 0, maximumBytes: body.count
        )
        XCTAssertEqual(chunks.count, 1)
        XCTAssertEqual(chunks[0].body, body)
        XCTAssertEqual(chunks[0].pointIndices, [0])
        XCTAssertEqual(chunks[0].visitIndices, [])
        XCTAssertEqual(chunks[0].visitCount, 0)
        XCTAssertEqual(chunks[0].sourceTime, Date(timeIntervalSince1970: 1_700_000_000))
    }

    func testSmallOtherFormatRemainsAnUnchangedBody() throws {
        let body = Data("timestamp,latitude,longitude\n1700000000,1,2\n".utf8)
        let chunks = try WebhookJSONPartitioner.boundedPayloads(
            body, pointCount: 1, visitCount: 0, maximumBytes: body.count
        )
        XCTAssertEqual(chunks.count, 1)
        XCTAssertEqual(chunks[0].body, body)
        XCTAssertEqual(chunks[0].pointIndices, [0])
        XCTAssertEqual(chunks[0].visitIndices, [])
        XCTAssertNil(chunks[0].sourceTime)
        assertError(.invalidEnvelope, body: body, pointCount: 1, visitCount: 0,
                    maximumBytes: body.count - 1)
    }

    func testMixedHistoryPreservesWholeRecordsUnknownFieldsAndLocalCounts() throws {
        let points: [[String: Any]] = (0..<20).map { index in
            ["nativeID": "point-\(index)", "timestampUnix": 1_700_000_000 + index,
             "latitude": 1.25, "longitude": -2.5,
             "unknown": ["nested": [NSNull(), true, "🧭\n\"original\"", index] as [Any],
                         "text": String(repeating: "p", count: 40)] as [String: Any]]
        }
        let visits: [[String: Any]] = (0..<3).map { index in
            ["nativeID": "visit-\(index)", "arrivalDate": "2020-01-01T00:00:00Z",
             "unknownVisit": ["notes": ["complete", "unchanged"], "ordinal": index] as [String: Any]]
        }
        let extra: [String: Any] = [
            "unknownExportField": ["keep": [true, NSNull(), "native"] as [Any]],
            "dateRange": ["earliest": "original start", "latest": "original end"]
        ]
        let original = envelope(points: points, visits: visits, extra: extra)
        let body = try encode(original)
        let limit = 900
        let chunks = try WebhookJSONPartitioner.boundedPayloads(
            body, pointCount: points.count, visitCount: visits.count, maximumBytes: limit
        )
        XCTAssertGreaterThan(chunks.count, 1)
        var restoredPoints: [[String: Any]] = [], restoredVisits: [[String: Any]] = []
        var restoredIndices: [Int] = []
        var restoredVisitIndices: [Int] = []
        for chunk in chunks {
            XCTAssertLessThanOrEqual(chunk.body.count, limit)
            let object = try decode(chunk.body)
            let localPoints = try XCTUnwrap(object["points"] as? [[String: Any]])
            let localVisits = try XCTUnwrap(object["visits"] as? [[String: Any]])
            XCTAssertFalse(localPoints.isEmpty && localVisits.isEmpty)
            XCTAssertEqual(object["exportDate"] as? String, exportDate)
            XCTAssertEqual(object["unknownExportField"] as? NSDictionary,
                           original["unknownExportField"] as? NSDictionary)
            XCTAssertEqual(object["dateRange"] as? NSDictionary, original["dateRange"] as? NSDictionary)
            XCTAssertEqual(object["totalPoints"] as? Int, localPoints.count)
            XCTAssertEqual(object["totalVisits"] as? Int, localVisits.count)
            XCTAssertEqual(chunk.visitCount, localVisits.count)
            XCTAssertEqual(chunk.pointIndices.count, localPoints.count)
            XCTAssertEqual(chunk.visitIndices.count, localVisits.count)
            XCTAssertEqual(chunk.pointIndices, chunk.pointIndices.sorted())
            XCTAssertEqual(chunk.visitIndices, chunk.visitIndices.sorted())
            for (index, point) in zip(chunk.pointIndices, localPoints) {
                XCTAssertEqual(point as NSDictionary, points[index] as NSDictionary)
            }
            for (index, visit) in zip(chunk.visitIndices, localVisits) {
                XCTAssertEqual(visit as NSDictionary, visits[index] as NSDictionary)
            }
            restoredPoints += localPoints
            restoredVisits += localVisits
            restoredIndices += chunk.pointIndices
            restoredVisitIndices += chunk.visitIndices
        }
        XCTAssertEqual(ordered(restoredPoints), ordered(points))
        XCTAssertEqual(ordered(restoredVisits), ordered(visits))
        XCTAssertEqual(restoredIndices.sorted(), Array(points.indices))
        XCTAssertEqual(restoredVisitIndices.sorted(), Array(visits.indices))
    }

    func testVisitsOnlyHistoryKeepsEveryVisitAndItsOriginalExportTime() throws {
        let visits: [[String: Any]] = (0..<20).map { index in
            ["nativeID": "visit-\(index)", "arrivalDate": "2020-01-01T00:00:00.250Z",
             "notes": String(repeating: "complete", count: 8), "unknown": ["ordinal": index]]
        }
        let body = try encode(envelope(points: [], visits: visits))
        let chunks = try WebhookJSONPartitioner.boundedPayloads(
            body, pointCount: 0, visitCount: visits.count, maximumBytes: 500
        )
        XCTAssertGreaterThan(chunks.count, 1)
        var restored: [[String: Any]] = []
        var restoredVisitIndices: [Int] = []
        for chunk in chunks {
            let object = try decode(chunk.body)
            XCTAssertLessThanOrEqual(chunk.body.count, 500)
            XCTAssertTrue(chunk.pointIndices.isEmpty)
            XCTAssertEqual(object["totalPoints"] as? Int, 0)
            XCTAssertEqual(object["exportDate"] as? String, exportDate)
            let local = try XCTUnwrap(object["visits"] as? [[String: Any]])
            XCTAssertEqual(chunk.visitCount, local.count)
            XCTAssertEqual(chunk.visitIndices.count, local.count)
            XCTAssertEqual(chunk.visitIndices, chunk.visitIndices.sorted())
            XCTAssertEqual(object["totalVisits"] as? Int, local.count)
            XCTAssertEqual(chunk.sourceTime, Date(timeIntervalSince1970: 1_577_836_800.25))
            restored += local
            restoredVisitIndices += chunk.visitIndices
        }
        XCTAssertEqual(ordered(restored), ordered(visits))
        XCTAssertEqual(restoredVisitIndices.sorted(), Array(visits.indices))
    }

    func testOneByteBelowACompleteEnvelopeSplitsOnlyAtRecordBoundaries() throws {
        let points: [[String: Any]] = (0..<2).map {
            ["nativeID": "point-\($0)", "timestampUnix": 1_700_000_000 + $0,
             "notes": String(repeating: "x", count: 80)]
        }
        let body = try encode(envelope(points: points, visits: []))
        let exact = try WebhookJSONPartitioner.boundedPayloads(
            body, pointCount: 2, visitCount: 0, maximumBytes: body.count
        )
        XCTAssertEqual(exact.count, 1)
        XCTAssertEqual(exact[0].body, body)
        let split = try WebhookJSONPartitioner.boundedPayloads(
            body, pointCount: 2, visitCount: 0, maximumBytes: body.count - 1
        )
        XCTAssertEqual(split.count, 2)
        XCTAssertTrue(split.allSatisfy { $0.body.count < body.count && $0.pointIndices.count == 1 })
        XCTAssertEqual(split.flatMap { $0.pointIndices }.sorted(), [0, 1])
        let single = try encode(envelope(points: [points[0]], visits: []))
        assertError(.tooLarge, body: single, pointCount: 1, visitCount: 0,
                    maximumBytes: single.count - 1)
    }

    func testEnvelopeMetadataCannotBeDroppedToMakeARecordFit() throws {
        let smallPoint: [String: Any] = ["nativeID": "small", "timestampUnix": 1_700_000_000]
        XCTAssertLessThan(try encode(smallPoint).count, 512)
        let metadata: [String: Any] = ["unknownExportField": String(repeating: "m", count: 2_048)]
        let body = try encode(envelope(points: [smallPoint], visits: [], extra: metadata))
        assertError(.tooLarge, body: body, pointCount: 1, visitCount: 0, maximumBytes: 512)
        let metadataOnly = try encode(envelope(points: [], visits: [], extra: metadata))
        assertError(.tooLarge, body: metadataOnly, pointCount: 0, visitCount: 0, maximumBytes: 512)
    }

    func testIndivisibleOversizedPointOrVisitReturnsNoPartialPartition() throws {
        let oversized: [String: Any] = ["nativeID": "large", "timestampUnix": 1_700_000_000,
                                       "unknown": ["text": String(repeating: "x", count: 2_048)]]
        let small: [String: Any] = ["nativeID": "small", "timestampUnix": 1_800_000_000]
        let points = try encode(envelope(points: [oversized, small], visits: []))
        assertError(.tooLarge, body: points, pointCount: 2, visitCount: 0, maximumBytes: 512)
        let visits = try encode(envelope(points: [], visits: [oversized, small]))
        assertError(.tooLarge, body: visits, pointCount: 0, visitCount: 2, maximumBytes: 512)
    }

    func testOversizedInvalidEnvelopeCannotLoseUnrecognizedRecords() throws {
        let point: [String: Any] = ["nativeID": "point", "notes": String(repeating: "x", count: 512)]
        let body = try encode(envelope(points: [point], visits: []))
        assertError(.invalidEnvelope, body: body, pointCount: 2, visitCount: 0, maximumBytes: 128)
        var malformed = envelope(points: [], visits: [])
        malformed["points"] = [point, "not a point object"] as [Any]
        let malformedBody = try encode(malformed)
        assertError(.invalidEnvelope, body: malformedBody, pointCount: 2, visitCount: 0, maximumBytes: 128)
        var missingDate = envelope(points: [point], visits: [])
        missingDate.removeValue(forKey: "exportDate")
        assertError(.invalidEnvelope, body: try encode(missingDate), pointCount: 1, visitCount: 0,
                    maximumBytes: 128)
    }
}

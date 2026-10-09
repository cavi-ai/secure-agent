import XCTest
@testable import SecureAgentMenubar

final class IncidentRemediationTests: XCTestCase {
    func testIncidentKeepsReportedRemediationSeparateFromResolution() throws {
        let data = Data(#"{"id":"incident","flag_id":"flag","pid":1,"agent":"claude","timestamp":"2026-10-09T12:00:00Z","rule":"read","summary":"Incident","risk":"HIGH","touched_files":[],"connections":[],"rotate_list":[],"workflow":{"status":"open"},"remediation":{"revision":1,"evidence_revision":"evidence","steps":[{"id":"step","item":{"id":"key","category":"SSH_KEYS","name":"Key","risk":"HIGH","description":"Review","action":"Revoke key"},"status":"reported","verification":"unverified","reported_at":"2026-10-09T12:00:00Z","newer_evidence":true}]}}"#.utf8)
        let incident = try JSONDecoder().decode(IncidentReportModel.self, from: data)
        let saved = try XCTUnwrap(JSONSerialization.jsonObject(with: JSONEncoder().encode(incident)) as? [String: Any])
        let remediation = try XCTUnwrap(saved["remediation"] as? [String: Any])
        let steps = try XCTUnwrap(remediation["steps"] as? [[String: Any]])
        XCTAssertEqual(steps.first?["status"] as? String, "reported")
        XCTAssertEqual(steps.first?["verification"] as? String, "unverified")
        XCTAssertEqual(incident.workflow?.status, "open")
    }
}

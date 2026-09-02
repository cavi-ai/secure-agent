import XCTest
@testable import SecureAgentMenubar

final class GuardTests: XCTestCase {
    func testDecodePending() throws {
        let json = #"[{"id":"p1","agent":"claude","tool":"Read","path":"/Users/x/.aws/credentials","rule_id":"cloud-creds","ts":"2026-09-01T00:00:00Z"}]"#
        let items = try JSONDecoder().decode([GuardPending].self, from: Data(json.utf8))
        XCTAssertEqual(items.first?.ruleID, "cloud-creds")
        XCTAssertEqual(items.first?.agent, "claude")
    }

    func testResolveRequestEncodesScope() throws {
        let data = try JSONEncoder().encode(GuardResolveRequest(id: "p1", verdict: "allow", scope: "always"))
        let s = String(decoding: data, as: UTF8.self)
        XCTAssertTrue(s.contains("\"scope\":\"always\""))
        XCTAssertTrue(s.contains("\"verdict\":\"allow\""))
    }

    func testClassicsAreThreePromptRules() {
        XCTAssertEqual(SetupManager.guardClassics.map { $0.ruleID }.sorted(),
                       ["cloud-creds", "keychain", "ssh-keys"])
        XCTAssertTrue(SetupManager.guardClassics.allSatisfy { $0.mode == "prompt" })
    }
}

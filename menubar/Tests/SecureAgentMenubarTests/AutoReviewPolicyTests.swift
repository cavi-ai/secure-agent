import XCTest
@testable import SecureAgentMenubar

final class AutoReviewPolicyTests: XCTestCase {
    func testExistingConfigurationKeepsReviewDefaults() throws {
        let policy = try AutoReviewPolicy.read("system_agent:\n  auto_review: true\n  model: qwen3\n")
        XCTAssertEqual(policy.minimumSeverity, 2)
        XCTAssertTrue(policy.excludedRules.isEmpty)
    }

    func testPolicyRoundTripPreservesUnrelatedConfigurationAndUnknownRules() throws {
        let yaml = "# personal config\nsystem_agent:\n  model: qwen3\n  auto_review_min_severity: 2 # cutoff\n  auto_review_excluded_rules:\n    - 'future-rule'\n    - secret-in-transcript\n  endpoint: http://127.0.0.1:11434\nadvisor:\n  enabled: true\n"
        var policy = try AutoReviewPolicy.read(yaml)
        XCTAssertEqual(policy.excludedRules, ["future-rule", "secret-in-transcript"])
        policy.minimumSeverity = 3
        policy.excludedRules.removeAll { $0 == "secret-in-transcript" }
        let updated = try policy.updating(yaml)
        XCTAssertTrue(updated.contains("# personal config\n"))
        XCTAssertTrue(updated.contains("model: qwen3\n"))
        XCTAssertTrue(updated.contains("endpoint: http://127.0.0.1:11434\nadvisor:\n  enabled: true\n"))
        XCTAssertEqual(try AutoReviewPolicy.read(updated), policy)
        XCTAssertFalse(updated.contains("    - secret-in-transcript"))
    }

    func testInlineListsAndComments() throws {
        let policy = try AutoReviewPolicy.read("system_agent:\n  auto_review_min_severity: 1\n  auto_review_excluded_rules: [\"tcc-tamper\", keychain-access] # types\n")
        XCTAssertEqual(policy.minimumSeverity, 1)
        XCTAssertEqual(policy.excludedRules, ["tcc-tamper", "keychain-access"])
    }

    func testBlockListWithCommentsAndIndentlessEntriesIsFullyReplaced() throws {
        let yaml = "system_agent:\n  auto_review_excluded_rules:\n  - keychain-access\n\n  # keep this explanatory comment\n  - tcc-tamper\n  model: qwen3\n"
        var policy = try AutoReviewPolicy.read(yaml)
        XCTAssertEqual(policy.excludedRules, ["keychain-access", "tcc-tamper"])
        policy.excludedRules = []
        let updated = try policy.updating(yaml)
        XCTAssertEqual(try AutoReviewPolicy.read(updated), policy)
        XCTAssertFalse(updated.contains("- keychain-access"))
        XCTAssertFalse(updated.contains("- tcc-tamper"))
        XCTAssertTrue(updated.contains("  model: qwen3\n"))
    }

    func testAbsentBlockCanBeCreated() throws {
        let policy = AutoReviewPolicy(minimumSeverity: 3, excludedRules: ["keychain-access"])
        let updated = try policy.updating("proxy_enabled: false\n")
        XCTAssertTrue(updated.hasPrefix("proxy_enabled: false\n"))
        XCTAssertEqual(try AutoReviewPolicy.read(updated), policy)
    }

    func testUnsupportedOrInvalidPolicyIsNeverOverwritten() {
        for yaml in [
            "system_agent: {auto_review: true}\n",
            "system_agent:\n  auto_review_min_severity: 4\n",
            "system_agent:\n  auto_review_min_severity: '3'\n",
            "system_agent:\n  auto_review_min_severity: 3\n  auto_review_min_severity: 1\n",
            "system_agent:\n  auto_review_excluded_rules: *shared\n",
            "system_agent:\n  auto_review_excluded_rules: [\"\"]\n"
        ] {
            XCTAssertThrowsError(try AutoReviewPolicy.read(yaml), yaml)
            XCTAssertThrowsError(try AutoReviewPolicy().updating(yaml), yaml)
        }
    }
}

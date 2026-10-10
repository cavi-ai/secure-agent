import XCTest
@testable import SecureAgentMenubar

final class SystemAgentDebugTests: XCTestCase {
    func testDebugPreservesOtherSettings() throws {
        let yaml = "proxy_enabled: true\nsystem_agent:\n  enabled: true\n  endpoint: \"http://localhost:11434\"\n  future: value\n  debug: false\nadvisor:\n  debug: false\n"
        let updated = try SetupManager.systemAgentDebugUpdating(yaml, enabled: true)
        XCTAssertTrue(SetupManager.systemAgentConfigIsEnabled(updated, key: "debug"))
        XCTAssertTrue(updated.contains("  future: value\n"))
        XCTAssertTrue(updated.contains("  endpoint: \"http://localhost:11434\"\n"))
        XCTAssertTrue(updated.hasSuffix("advisor:\n  debug: false\n"))
    }

    func testAmbiguousDebugConfigurationIsRefused() {
        for yaml in ["system_agent: {debug: false}\n", "system_agent:\n  debug: false\n  debug: true\n", "system_agent:\nsystem_agent:\n", "\"system_agent\":\n  debug: false\n", "system_agent :\n  debug: false\n", "---\nsystem_agent:\n"] {
            XCTAssertThrowsError(try SetupManager.systemAgentDebugUpdating(yaml, enabled: true), yaml)
        }
    }
}

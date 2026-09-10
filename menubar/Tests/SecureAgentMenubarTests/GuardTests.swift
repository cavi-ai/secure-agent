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

    func testClassicsAreFourPromptRules() {
        XCTAssertEqual(SetupManager.guardClassics.map { $0.ruleID }.sorted(),
                       ["cloud-creds", "harness-config", "keychain", "ssh-keys"])
        XCTAssertTrue(SetupManager.guardClassics.allSatisfy { $0.mode == "prompt" })
    }

    // MARK: - advisor config YAML helpers

    func testAdvisorConfigEnableAppendsBlockWhenAbsent() {
        let out = SetupManager.advisorConfigUpdating("proxy_enabled: true\n", enabled: true)
        XCTAssertTrue(SetupManager.advisorConfigIsEnabled(out))
        XCTAssertTrue(out.contains("proxy_enabled: true")) // untouched
        XCTAssertTrue(out.contains("endpoint: \"http://127.0.0.1:8080\""))
    }

    func testAdvisorConfigFlipsEnabledLineOnly() {
        let yaml = "proxy_enabled: true\nadvisor:\n  enabled: false\n  endpoint: \"http://127.0.0.1:8080\"\n  model: \"qwen\"\n"
        let out = SetupManager.advisorConfigUpdating(yaml, enabled: true)
        XCTAssertTrue(SetupManager.advisorConfigIsEnabled(out))
        XCTAssertTrue(out.contains("model: \"qwen\"")) // other keys preserved
        // and flipping back works
        let off = SetupManager.advisorConfigUpdating(out, enabled: false)
        XCTAssertFalse(SetupManager.advisorConfigIsEnabled(off))
    }

    func testAdvisorConfigMissingFileIsDisabled() {
        XCTAssertFalse(SetupManager.advisorConfigIsEnabled(""))
        XCTAssertFalse(SetupManager.advisorConfigIsEnabled("proxy_enabled: true\n"))
    }

    func testAdvisorConfigIgnoresKeysOutsideBlock() {
        // An `enabled:` line in another section must not count.
        let yaml = "firewall:\n  enabled: true\nadvisor:\n  enabled: false\n"
        XCTAssertFalse(SetupManager.advisorConfigIsEnabled(yaml))
    }

    // MARK: - advisor full-block writer (Settings advisor pane)

    func testAdvisorConfigSettingManagedWritesManagedBlock() {
        let out = SetupManager.advisorConfigSetting("proxy_enabled: true\n", mode: .managed, endpoint: nil,
                                                    model: "mlx-community/Qwen3-4B-4bit")
        XCTAssertTrue(out.contains("managed: true"))
        XCTAssertTrue(out.contains("managed_model: \"mlx-community/Qwen3-4B-4bit\""))
        XCTAssertFalse(out.contains("endpoint:")) // managed derives it
        XCTAssertTrue(SetupManager.advisorConfigIsEnabled(out))
        XCTAssertTrue(out.contains("proxy_enabled: true"))
    }

    func testAdvisorConfigSettingExistingReplacesOldBlock() {
        let old = "advisor:\n  enabled: true\n  endpoint: \"http://127.0.0.1:8080\"\n  model: \"old\"\nfirewall:\n  mode: monitor\n"
        let out = SetupManager.advisorConfigSetting(old, mode: .existing,
                                                    endpoint: "http://127.0.0.1:11434", model: "qwen3:4b")
        XCTAssertTrue(out.contains("endpoint: \"http://127.0.0.1:11434\""))
        XCTAssertTrue(out.contains("model: \"qwen3:4b\""))
        XCTAssertFalse(out.contains("model: \"old\""))
        XCTAssertFalse(out.contains("managed: true"))
        XCTAssertTrue(out.contains("firewall:\n  mode: monitor")) // untouched
    }

    func testAdvisorDiscoveryDecodes() throws {
        let json = #"{"servers":[{"endpoint":"http://127.0.0.1:11434","kind":"ollama","models":["qwen3:4b"]}],"managed_models":["mlx-community/Qwen3-4B-4bit"]}"#
        let d = try JSONDecoder().decode(AdvisorDiscovery.self, from: Data(json.utf8))
        XCTAssertEqual(d.servers.first?.kind, "ollama")
        XCTAssertEqual(d.servers.first?.models, ["qwen3:4b"])
        XCTAssertEqual(d.managedModels, ["mlx-community/Qwen3-4B-4bit"])
    }
}

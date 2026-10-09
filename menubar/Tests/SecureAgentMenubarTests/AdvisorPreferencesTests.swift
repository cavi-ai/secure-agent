import XCTest
@testable import SecureAgentMenubar

final class AdvisorPreferencesTests: XCTestCase {
    func testModelChangePreservesRuntimeAndUnknownSettings() throws {
        let yaml = "advisor:\n  enabled: true\n  model: old\n  endpoint: http://127.0.0.1:8080\n  timeout_ms: 120000\n  classifier_endpoint: http://127.0.0.1:8009\n  classifier_model: kev-latest\n  debug: true\n  future_setting: keep\nfirewall:\n  mode: monitor\n"
        let changed = try SetupManager.advisorConfigSetting(yaml, mode: .managed, endpoint: nil, model: "local-model")
        XCTAssertTrue(changed.contains("  timeout_ms: 120000\n"))
        XCTAssertTrue(changed.contains("  classifier_endpoint: http://127.0.0.1:8009\n"))
        XCTAssertTrue(changed.contains("  debug: true\n"))
        XCTAssertTrue(changed.contains("  future_setting: keep\n"))
        XCTAssertTrue(changed.contains("firewall:\n  mode: monitor\n"))
    }

    func testRuntimeRoundTripAndDisableClassifier() throws {
        let prefs = AdvisorPreferences(timeoutMS: 120000, classifierEndpoint: "http://127.0.0.1:8009", classifierModel: "kev-latest", debug: true)
        let written = try prefs.updating("advisor:\n  enabled: false\n  model: local\n")
        XCTAssertEqual(try AdvisorPreferences.read(written), prefs)
        XCTAssertTrue(written.contains("enabled: false"))
        var disabled = prefs
        disabled.classifierEndpoint = ""
        let next = try disabled.updating(written)
        XCTAssertEqual(try AdvisorPreferences.read(next).classifierEndpoint, "")
        XCTAssertTrue(next.contains("model: local"))
    }

    func testUnsafeEndpointsAndAmbiguousYAMLDoNotRewrite() throws {
        for endpoint in ["https://example.com", "http://localhost.evil:8009", "http://user:pass@127.0.0.1:8009"] {
            XCTAssertThrowsError(try AdvisorPreferences(classifierEndpoint: endpoint).updating(""))
        }
        for yaml in ["advisor: {enabled: true}\n", "advisor :\n  enabled: true\n", "'advisor':\n  enabled: true\n", "{advisor: {enabled: true}}\n", "advisor:\n  debug: true\n  debug: false\n", "advisor:\n  debug:\n    nested: true\n", "advisor:\nadvisor:\n"] {
            XCTAssertThrowsError(try AdvisorPreferences.read(yaml))
            XCTAssertThrowsError(try AdvisorPreferences().updating(yaml))
        }
        XCTAssertTrue(AdvisorPreferences.isLoopbackEndpoint("http://[::1]:8009"))
        XCTAssertEqual(try AdvisorPreferences.read("# empty overlay\n").timeoutMS, 60000)
    }

    func testQuotedScalarsAndDisabledClassifierSurviveEditing() throws {
        let yaml = "advisor:\n  classifier_endpoint: # disabled\n  classifier_model: 'kev-latest' # user's choice\n  timeout_ms: 120000 # cold loading\n  debug: false\n"
        var prefs = try AdvisorPreferences.read(yaml)
        XCTAssertEqual(prefs.classifierEndpoint, "")
        XCTAssertEqual(prefs.classifierModel, "kev-latest")
        prefs.debug = true
        let edited = try prefs.updating(yaml)
        XCTAssertEqual(try AdvisorPreferences.read(edited), prefs)
    }

    @MainActor
    func testLocalClassifierSetupProbe() async throws {
        guard let endpoint = ProcessInfo.processInfo.environment["SECURE_AGENT_TEST_CLASSIFIER_ENDPOINT"] else {
            throw XCTSkip("opt-in check against a running local classifier")
        }
        let result = await AdvisorOptionsView.checkClassifier(endpoint: endpoint, model: "kev-latest")
        XCTAssertTrue(result.hasPrefix("Classifier connected"), result)
    }
}

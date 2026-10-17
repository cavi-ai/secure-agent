import XCTest
@testable import SecureAgentMenubar

@MainActor
final class SetupProcessTests: XCTestCase {
    /// The administrator prompt for the old helper runs off the main actor:
    /// the menu bar keeps running while the prompt is open, a cancel leaves no
    /// error, and a failure is reported.
    func testLegacyHelperRemovalLeavesTheMainActorFree() async throws {
        let defaults = try XCTUnwrap(UserDefaults(suiteName: "SetupProcessTests.\(UUID().uuidString)"))
        let setup = SetupManager(esService: FakeESService(), defaults: defaults, plistPresent: { false },
                                 openPane: { _ in XCTFail("No permission pane should open") },
                                 appURL: URL(fileURLWithPath: "/fixture/Secure Agent.app"), deferAutomaticTelemetry: true)
        for (stderr, failed) in [("execution error: User canceled. (-128)", false), ("execution error: boom", true)] {
            let prompt = PromptGate()
            setup.runProcess = { bin, _ in
                XCTAssertEqual(bin, "/usr/bin/osascript")
                await prompt.open()
                return (1, "", stderr)
            }
            let removal = Task { await setup.removeLegacyESHelper() }
            await prompt.opened() // the main actor runs this while the prompt is open
            await prompt.close()
            await removal.value
            XCTAssertEqual(setup.lastError?.contains("old helper removal failed") ?? false, failed, stderr)
        }
    }
}

/// Holds a fake administrator prompt open until the test closes it.
private actor PromptGate {
    private var isOpen = false
    private var openers: [CheckedContinuation<Void, Never>] = []
    private var closer: CheckedContinuation<Void, Never>?

    func open() async {
        isOpen = true
        openers.forEach { $0.resume() }
        openers = []
        await withCheckedContinuation { closer = $0 }
    }

    func opened() async {
        if isOpen { return }
        await withCheckedContinuation { openers.append($0) }
    }

    func close() {
        closer?.resume()
        closer = nil
    }
}

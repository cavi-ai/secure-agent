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

    func testCLIInstallReportsTheLinkInsteadOfStayingSilent() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let cli = root.appendingPathComponent("Secure Agent.app/Contents/Helpers/secure-agent")
        try FileManager.default.createDirectory(at: cli.deletingLastPathComponent(), withIntermediateDirectories: true)
        try Data("cli".utf8).write(to: cli)
        let home = root.appendingPathComponent("home").path
        let link = home + "/.local/bin/secure-agent"
        XCTAssertEqual(SetupManager.cliLinkState(bundledCLI: nil, linkPath: link), .unavailable)
        XCTAssertEqual(SetupManager.cliLinkState(bundledCLI: cli.path, linkPath: link), .missing)

        let defaults = try XCTUnwrap(UserDefaults(suiteName: "SetupProcessTests.cli.\(UUID().uuidString)"))
        let setup = SetupManager(esService: FakeESService(), defaults: defaults, configurationHome: home,
                                 plistPresent: { false }, openPane: { _ in }, appURL: root.appendingPathComponent("Secure Agent.app"),
                                 deferAutomaticTelemetry: true)
        XCTAssertEqual(setup.cliLinkState(), .missing)
        await setup.installCLI()
        XCTAssertNil(setup.cliFailure)
        XCTAssertFalse(setup.cliInstalling)
        XCTAssertEqual(setup.cliLinkState(), .installed)
        let destination = try FileManager.default.destinationOfSymbolicLink(atPath: link)
        XCTAssertEqual(URL(fileURLWithPath: destination).standardizedFileURL.path, cli.standardizedFileURL.path)

        try Data("other".utf8).write(to: URL(fileURLWithPath: home + "/.local/bin/other-command"))
        try FileManager.default.removeItem(atPath: link)
        try FileManager.default.createSymbolicLink(atPath: link, withDestinationPath: home + "/.local/bin/other-command")
        XCTAssertEqual(setup.cliLinkState(), .otherFile)
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

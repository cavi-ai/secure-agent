import Darwin
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

    func testAdvisorSavedChoiceUpdatesImmediately() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let defaults = try XCTUnwrap(UserDefaults(suiteName: UUID().uuidString))
        let setup = SetupManager(esService: FakeESService(), defaults: defaults, configurationHome: root.path,
                                 plistPresent: { false }, openPane: { _ in }, deferAutomaticTelemetry: true)
        setup.setAdvisorConfig(mode: .existing, endpoint: "https://localhost:444/prefix", model: "chosen")
        XCTAssertEqual(setup.advisorPersisted.mode, "existing")
        XCTAssertEqual(setup.advisorPersisted.endpoint, "https://localhost:444/prefix")
        XCTAssertEqual(setup.advisorPersisted.model, "chosen")
    }

    func testCLIRollbackPreservesConcurrentReplacement() throws {
        let fm = FileManager.default
        let home = fm.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? fm.removeItem(at: home) }
        let bin = home.appendingPathComponent(".local/bin")
        try fm.createDirectory(at: bin, withIntermediateDirectories: true)
        let link = bin.appendingPathComponent("secure-agent").path
        try fm.createSymbolicLink(atPath: link, withDestinationPath: "old-relative")
        var temporary = ""
        var calls = 0
        var operationError: Error?
        XCTAssertThrowsError(try SetupManager.replaceCLISymlink(at: link, target: "/fixture/secure-agent") { temp, destination in
            calls += 1
            temporary = temp
            do {
                try fm.removeItem(atPath: destination)
                try Data((calls == 1 ? "first" : "second").utf8).write(to: URL(fileURLWithPath: destination))
                return renamex_np(temp, destination, UInt32(RENAME_SWAP))
            } catch {
                operationError = error
                return -1
            }
        }) { error in
            XCTAssertTrue(error.localizedDescription.contains(temporary))
        }
        XCTAssertNil(operationError)
        XCTAssertEqual(calls, 2)
        XCTAssertEqual(try String(contentsOfFile: link, encoding: .utf8), "first")
        XCTAssertEqual(try String(contentsOfFile: temporary, encoding: .utf8), "second")
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
        XCTAssertEqual(setup.cliLinkState(), .otherLink)
        await setup.installCLI()
        XCTAssertNil(setup.cliFailure)
        XCTAssertEqual(setup.cliLinkState(), .installed)
        await setup.installCLI()
        XCTAssertNil(setup.cliFailure)
        try FileManager.default.removeItem(atPath: link)
        try FileManager.default.createSymbolicLink(atPath: link, withDestinationPath: "missing-relative")
        await setup.installCLI()
        XCTAssertEqual(setup.cliLinkState(), .installed)
        try FileManager.default.removeItem(atPath: link)
        try Data("protected".utf8).write(to: URL(fileURLWithPath: link))
        await setup.installCLI()
        XCTAssertNotNil(setup.cliFailure)
        XCTAssertEqual(try String(contentsOfFile: link, encoding: .utf8), "protected")
        try FileManager.default.removeItem(atPath: link)
        try FileManager.default.createDirectory(atPath: link, withIntermediateDirectories: false)
        try Data("sentinel".utf8).write(to: URL(fileURLWithPath: link + "/sentinel"))
        await setup.installCLI()
        XCTAssertNotNil(setup.cliFailure)
        XCTAssertEqual(try String(contentsOfFile: link + "/sentinel", encoding: .utf8), "sentinel")
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

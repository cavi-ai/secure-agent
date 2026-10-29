import XCTest
import AppKit
@testable import SecureAgentMenubar

@MainActor
final class GuardPromptPanelTests: XCTestCase {
    private let dayScope = GuardScopeChoice(kind: "exact", expiry: "24h")

    private static let githubRead = "GitHub content gh pr list --state open --json number,title,headRefName,mergeable,updatedAt --limit 30, GitHub"

    private func pending(ruleID: String = "ssh-keys", detail: String? = nil, advisor: GuardAdvice? = nil) -> GuardPending {
        GuardPending(id: "g1", agent: "claude", tool: "Read", path: "/Users/x/.ssh/id_ed25519", ruleID: ruleID, ts: "", scopeText: nil,
                     advisor: advisor,
                     availableScopes: [GuardScopeChoice(kind: "session", expiry: nil), dayScope, GuardScopeChoice(kind: "exact", expiry: "7d")],
                     readerExe: "/bin/cat", workspace: "/Users/x/code/app", sessionID: "5f2c9a1e-7b4d-4c1a-9e2f-0d8b6a3c4e11", detail: detail)
    }

    /// The hook's untrusted-egress request, as `gate_untrusted_egress` words it.
    private func egress(read: [String], scopes: [GuardScopeChoice]? = nil) -> GuardPending {
        GuardPending(id: "e1", agent: "claude", tool: "Artifact", path: "Artifact claude.ai", ruleID: "untrusted-egress", ts: "", scopeText: nil,
                     advisor: nil, availableScopes: scopes, readerExe: "/Applications/Claude.app/Contents/MacOS/claude",
                     workspace: "/Users/x/code/app", sessionID: "7734d6db-8a85-4628-9ff7-e5e370748540",
                     detail: "This session read untrusted content: \(read.joined(separator: "; ")). It now sends data out: Artifact claude.ai.")
    }

    func testUntrustedSourcesComeFromTheHookReason() {
        XCTAssertEqual(egress(read: [Self.githubRead]).untrustedSources, [Self.githubRead])
        XCTAssertEqual(egress(read: ["web page https://example.com/a", "image /repo/x.png, committed by someone"]).untrustedSources,
                       ["web page https://example.com/a", "image /repo/x.png, committed by someone"])
        XCTAssertNil(pending(detail: "This session read untrusted content: x. It now sends data out: y.").untrustedSources, "file rules have no sources")
        XCTAssertNil(pending(ruleID: "untrusted-egress", detail: "Some other reason.").untrustedSources)
    }

    func testUntrustedEgressPromptShowsWhatItReadAndDenies() throws {
        let choice = run(GuardPromptContent(pending: egress(read: [Self.githubRead]), inspectUnavailableReason: nil)) { panel in
            XCTAssertTrue(panel.isKeyWindow, "Return and Escape reach the prompt")
            XCTAssertEqual(panel.model.durations, [.once], "no recorded identity: once only")
            XCTAssertEqual(panel.model.allowNote, "Allow Once answers only this request.")
            try? self.capture(panel, "after-egress")
            NSApp.sendEvent(self.key(36, "\r", in: panel))
        }
        XCTAssertEqual(choice, .deny)
    }

    // Once per class: switching the policy back between tests delivers a
    // deactivation into the next test's modal session.
    nonisolated(unsafe) private static var policy: NSApplication.ActivationPolicy = .prohibited

    override class func setUp() {
        MainActor.assumeIsolated {
            _ = NSApplication.shared
            policy = NSApp.activationPolicy()
            NSApp.setActivationPolicy(.regular)
            NSApp.finishLaunching()
            NSApp.activate(ignoringOtherApps: true)
        }
    }

    override class func tearDown() {
        MainActor.assumeIsolated { _ = NSApp.setActivationPolicy(policy) }
    }

    private func key(_ code: UInt16, _ chars: String, in window: NSWindow) -> NSEvent {
        NSEvent.keyEvent(with: .keyDown, location: .zero, modifierFlags: [], timestamp: ProcessInfo.processInfo.systemUptime,
                         windowNumber: window.windowNumber, context: nil, characters: chars,
                         charactersIgnoringModifiers: chars, isARepeat: false, keyCode: code)!
    }

    /// Runs the real modal prompt and acts on it from inside its modal loop.
    private func run(_ content: GuardPromptContent, after: @escaping (GuardPromptPanel) -> Void) -> GuardPromptChoice {
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.4) {
            guard let panel = NSApp.modalWindow as? GuardPromptPanel else {
                XCTFail("the modal window is not the guard prompt panel"); NSApp.abortModal(); return
            }
            after(panel)
        }
        return GuardPromptPanel.run(content)
    }

    private func capture(_ panel: NSWindow, _ name: String) throws {
        let dir = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent(".build/guard-qa")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        guard CGPreflightScreenCaptureAccess() else { return }
        RunLoop.main.run(until: Date().addingTimeInterval(0.8))
        let shot = Process()
        shot.executableURL = URL(fileURLWithPath: "/usr/sbin/screencapture")
        shot.arguments = ["-x", "-o", "-l", String(panel.windowNumber), dir.appendingPathComponent(name + ".png").path]
        try shot.run(); shot.waitUntilExit()
        XCTAssertEqual(shot.terminationStatus, 0)
    }

    func testReturnDeniesThroughTheModalPanel() throws {
        var width: CGFloat = 0
        let choice = run(GuardPromptContent(pending: pending(advisor: GuardAdvice(assessment: "suspicious", confidence: 0.7, rationale: "Private SSH key outside the project.")),
                                            inspectUnavailableReason: nil)) { panel in
            width = panel.frame.width
            XCTAssertTrue(panel.isKeyWindow, "Return and Escape reach the prompt")
            try? self.capture(panel, "after")
            NSApp.sendEvent(self.key(36, "\r", in: panel))
        }
        XCTAssertEqual(choice, .deny)
        XCTAssertEqual(width, GuardPromptPanel.width)
    }

    func testEscapeDeniesThroughTheModalPanel() {
        let choice = run(GuardPromptContent(pending: pending(), inspectUnavailableReason: nil)) { panel in
            XCTAssertTrue(panel.isKeyWindow, "Return and Escape reach the prompt")
            NSApp.sendEvent(self.key(53, "\u{1b}", in: panel))
        }
        XCTAssertEqual(choice, .deny)
    }

    func testChosenDurationIsTheAllowScope() throws {
        let choice = run(GuardPromptContent(pending: egress(read: [Self.githubRead, "web page https://example.com/page.html"], scopes: pending().availableScopes),
                                            inspectUnavailableReason: "Session identity unavailable")) { panel in
            XCTAssertEqual(panel.model.durations.map(\.label), ["Once", "This session", "24 hours", "7 days"])
            XCTAssertEqual(panel.model.allowTitle, "Allow Once")
            panel.model.duration = .scope(self.dayScope)
            let collapsed = panel.frame
            panel.model.showsDetails = true
            RunLoop.main.run(until: Date().addingTimeInterval(0.5))
            XCTAssertGreaterThan(panel.frame.height, collapsed.height, "details grow the panel")
            XCTAssertEqual(panel.frame.maxY, collapsed.maxY, accuracy: 0.5, "the top edge stays put")
            XCTAssertEqual(panel.model.allowTitle, "Allow for 24 hours")
            XCTAssertEqual(panel.model.allowNote, "Future access requires a separate confirmation.")
            try? self.capture(panel, "after-egress-details")
            panel.model.inspect() // unavailable: no answer
            panel.model.allow()
        }
        XCTAssertEqual(choice, .allow(dayScope))
    }

    func testWithdrawalAnswersNothing() {
        let choice = run(GuardPromptContent(pending: pending(), inspectUnavailableReason: nil)) { _ in NSApp.abortModal() }
        XCTAssertEqual(choice, .withdrawn)
    }
}

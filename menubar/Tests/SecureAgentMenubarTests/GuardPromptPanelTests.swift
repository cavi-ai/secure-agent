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

    func testUntrustedEgressPromptShowsWhatItReadAndDenies() async throws {
        let choice = await run(GuardPromptContent(pending: egress(read: [Self.githubRead]), inspectUnavailableReason: nil)) { panel in
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

    /// Shows the real prompt and acts on it once it is on screen.
    private func run(_ content: GuardPromptContent, after: @escaping (GuardPromptPanel) -> Void) async -> GuardPromptChoice {
        Task { @MainActor in
            try? await Task.sleep(nanoseconds: 400_000_000)
            guard let panel = GuardPromptPanel.shown else { XCTFail("the guard prompt panel is not shown"); return }
            after(panel)
        }
        return await GuardPromptPanel.present(content)
    }

    /// Saves a review screenshot to .build/guard-qa when screen capture is
    /// permitted; it is QA output, not an assertion.
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
    }

    /// Allow with a duration chosen in the prompt answers the request with
    /// that scope; no second confirmation opens over the prompt.
    func testChosenDurationAnswersWithoutASecondConfirmation() async {
        let session = GuardScopeChoice(kind: "session", expiry: nil)
        let client = StubDaemonClient()
        client.pending = [egress(read: [Self.githubRead], scopes: [session])]
        let state = AppState(client: client)
        let answerer = ModalAnswerer { panel in
            if panel.model.duration == .scope(session) { panel.model.allow() } else { panel.model.duration = .scope(session) }
        }
        state.fetch()
        let others = await answerer.wait(until: { !client.guardResolveCalls.isEmpty })
        XCTAssertEqual(others, [], "a second confirmation opened")
        XCTAssertEqual(client.guardResolveCalls.map { "\($0.verdict) \($0.scope)" }, ["allow session"])
    }

    /// Future access picked in the popover opens the same prompt with that
    /// duration selected; its Allow is the answer.
    func testPopoverFutureAccessOpensThePromptWithItsDuration() async {
        let client = StubDaemonClient()
        client.pending = [pending()]
        let state = AppState(client: client)
        state.seedPostureForTesting(nil, pendingGuard: pending())
        var allowTitle: String?
        let answerer = ModalAnswerer { panel in
            allowTitle = panel.model.allowTitle
            panel.model.allow()
        }
        Task { await state.resolvePendingGuard(id: "g1", verdict: "allow", scope: "exact", expiry: "24h") }
        let others = await answerer.wait(until: { !client.guardResolveCalls.isEmpty })
        XCTAssertEqual(others, [], "the popover opened a confirmation other than the guard prompt")
        XCTAssertEqual(allowTitle, "Allow for 24 hours")
        XCTAssertEqual(client.guardResolveCalls.map { "\($0.verdict) \($0.scope) \($0.expiry ?? "")" }, ["allow exact 24h"])
    }

    func testReturnDeniesThroughThePanel() async throws {
        var width: CGFloat = 0
        let choice = await run(GuardPromptContent(pending: pending(advisor: GuardAdvice(assessment: "suspicious", confidence: 0.7, rationale: "Private SSH key outside the project.")),
                                            inspectUnavailableReason: nil)) { panel in
            width = panel.frame.width
            try? self.capture(panel, "after")
            NSApp.sendEvent(self.key(36, "\r", in: panel))
        }
        XCTAssertEqual(choice, .deny)
        XCTAssertEqual(width, GuardPromptPanel.width)
    }

    func testEscapeDeniesThroughThePanel() async {
        let choice = await run(GuardPromptContent(pending: pending(), inspectUnavailableReason: nil)) { panel in
            NSApp.sendEvent(self.key(53, "\u{1b}", in: panel))
        }
        XCTAssertEqual(choice, .deny)
    }

    func testChosenDurationIsTheAllowScope() async throws {
        let choice = await run(GuardPromptContent(pending: egress(read: [Self.githubRead, "web page https://example.com/page.html"], scopes: pending().availableScopes),
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
            XCTAssertEqual(panel.model.allowNote, "Allows these sends from this tool for 24 hours. Executable signatures are not verified. Other sends still ask. Revoke under Protection → Rules & permissions.")
            try? self.capture(panel, "after-egress-details")
            panel.model.inspect() // unavailable: no answer
            panel.model.allow()
        }
        XCTAssertEqual(choice, .allow(dayScope))
    }

    /// The agent's app is in front when a guard request arrives: the prompt
    /// stays visible above it and on the Space in front.
    func testPromptStaysInFrontOfTheActiveApp() async {
        let choice = await run(GuardPromptContent(pending: egress(read: [Self.githubRead]), inspectUnavailableReason: nil)) { panel in
            XCTAssertGreaterThanOrEqual(panel.level.rawValue, NSWindow.Level.modalPanel.rawValue)
            XCTAssertTrue(panel.collectionBehavior.contains(.canJoinAllSpaces))
            XCTAssertTrue(panel.collectionBehavior.contains(.fullScreenAuxiliary))
            panel.withdraw()
        }
        XCTAssertEqual(choice, .withdrawn)
    }

    /// While the real prompt is up, polling continues: a request answered
    /// elsewhere closes it and nothing is submitted.
    func testPromptClosesWhenTheRequestIsAnsweredElsewhere() async {
        let client = StubDaemonClient()
        client.pending = [pending()]
        let state = AppState(client: client)
        state.fetch()
        for _ in 0..<100 where GuardPromptPanel.shown == nil { try? await Task.sleep(nanoseconds: 20_000_000) }
        XCTAssertNotNil(GuardPromptPanel.shown)
        client.pending = []
        await state.performFetch()
        for _ in 0..<100 where GuardPromptPanel.shown != nil { try? await Task.sleep(nanoseconds: 20_000_000) }
        XCTAssertNil(GuardPromptPanel.shown, "the prompt stayed up after the request left")
        XCTAssertNil(state.promptingIDForTesting)
        XCTAssertEqual(client.guardResolveCalls.count, 0)
    }

    func testWithdrawalAnswersNothing() async {
        let choice = await run(GuardPromptContent(pending: pending(), inspectUnavailableReason: nil)) { $0.withdraw() }
        XCTAssertEqual(choice, .withdrawn)
    }
}

/// Hands the shown guard prompt panel to `answer` every 20 ms; any modal
/// window is aborted and recorded.
@MainActor
private final class ModalAnswerer: NSObject {
    private let answer: (GuardPromptPanel) -> Void
    private let deadline = Date().addingTimeInterval(5)
    private var others: [String] = []
    private var timer: Timer?

    init(_ answer: @escaping (GuardPromptPanel) -> Void) {
        self.answer = answer
        super.init()
        let timer = Timer(timeInterval: 0.02, target: self, selector: #selector(tick), userInfo: nil, repeats: true)
        RunLoop.main.add(timer, forMode: .common)
        self.timer = timer
    }

    @objc private func tick() {
        if let window = NSApp.modalWindow {
            others.append(String(describing: type(of: window)))
            NSApp.abortModal()
            return
        }
        if let panel = GuardPromptPanel.shown, Date() < deadline { answer(panel) }
    }

    /// Waits for `done` or the deadline, then stops; returns the modal windows seen.
    func wait(until done: () -> Bool) async -> [String] {
        while !done(), Date() < deadline { try? await Task.sleep(nanoseconds: 20_000_000) }
        timer?.invalidate()
        return others
    }
}

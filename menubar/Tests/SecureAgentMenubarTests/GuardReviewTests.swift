import XCTest
import SwiftUI
@testable import SecureAgentMenubar

final class GuardReviewTests: XCTestCase {
    let pending = GuardPending(id: "request", agent: "claude", tool: "Read", path: "/workspace/app/.env", ruleID: "env-files", ts: "", scopeText: nil, advisor: nil, availableScopes: [.init(kind: "once", expiry: nil), .init(kind: "exact", expiry: "24h")], readerExe: "/bin/claude", workspace: "/workspace/app", sessionID: "session")

    func testFutureConfirmationBindsRecordedIdentityAndSelectedLifetime() throws {
        let text = try XCTUnwrap(pending.confirmation(scope: "exact", expiry: "24h"))
        for fact in ["Read", "/workspace/app/.env", "/workspace/app", "/bin/claude", "24 hours", "signatures are not verified"] { XCTAssertTrue(text.contains(fact), fact) }
        XCTAssertNil(pending.confirmation(scope: "exact", expiry: "7d"))
    }

    @MainActor
    func testRequestRendersAtPopoverWidth() async throws {
        _ = NSApplication.shared
        let policy = NSApp.activationPolicy()
        XCTAssertTrue(NSApp.setActivationPolicy(.regular))
        NSApp.finishLaunching()
        defer { NSApp.setActivationPolicy(policy) }
        let state = AppState.previewAttention()
        state.seedPostureForTesting(nil, pendingGuard: pending)
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
        try XCTUnwrap(bitmap.representation(using: .png, properties: [:])).write(to: dir.appendingPathComponent("access-request.png"))
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
    func testCancelledConsentAndExpiredRequestDoNotWrite() async {
        let client = StubDaemonClient()
        client.pending = [pending]
        let state = AppState(client: client)
        state.seedPostureForTesting(nil, pendingGuard: pending)
        await state.resolvePendingGuard(id: "request", verdict: "allow", scope: "exact", expiry: "24h", confirm: { _ in false })
        XCTAssertTrue(client.guardResolveCalls.isEmpty)
        client.pending = []
        await state.resolvePendingGuard(id: "request", verdict: "allow", scope: "exact", expiry: "24h", confirm: { _ in true })
        XCTAssertTrue(client.guardResolveCalls.isEmpty)
        XCTAssertEqual(state.guardRequestNotice, "Request no longer pending. No answer was submitted.")
    }

    @MainActor
    func testLiveRequestSubmitsExactConsentAndReadFailureDoesNotClaimSubmission() async {
        let client = StubDaemonClient()
        client.pending = [pending]
        let state = AppState(client: client)
        state.seedPostureForTesting(nil, pendingGuard: pending)
        await state.resolvePendingGuard(id: "request", verdict: "allow", scope: "exact", expiry: "24h", confirm: { _ in true })
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

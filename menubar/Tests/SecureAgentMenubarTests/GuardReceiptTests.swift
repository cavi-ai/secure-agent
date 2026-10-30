import XCTest
import SwiftUI
@testable import SecureAgentMenubar

final class GuardReceiptTests: XCTestCase {
    @MainActor
    func testGuardFeedbackRendersAtPopoverWidth() async throws {
        _ = NSApplication.shared
        let policy = NSApp.activationPolicy()
        XCTAssertTrue(NSApp.setActivationPolicy(.regular))
        NSApp.finishLaunching()
        NSApp.activate(ignoringOtherApps: true)
        defer { NSApp.setActivationPolicy(policy) }
        let client = StubDaemonClient()
        let state = AppState(client: client)
        for (name, error) in [("submitted", nil as Error?), ("unconfirmed", NSError(domain: "fixture", code: 1) as Error?)] {
            client.resolveGuardError = error
            state.seedPostureForTesting(nil, pendingGuard: GuardPending(id: "prompt", agent: "codex", tool: "Read", path: "/fixture", ruleID: "env", ts: "", scopeText: nil, advisor: nil, sessionID: "session"))
            client.pending = [state.pendingGuard!]
            await state.resolvePendingGuard(verdict: "allow", scope: "once")
            let controller = NSHostingController(rootView: ConsoleView(state: state, scrollable: false))
            let window = NSWindow(contentViewController: controller)
            window.isReleasedWhenClosed = false
            window.appearance = NSAppearance(named: .darkAqua)
            let size = controller.view.fittingSize
            window.setContentSize(NSSize(width: 340, height: size.height))
            window.makeKeyAndOrderFront(nil)
            try await Task.sleep(for: .milliseconds(200))
            controller.view.layoutSubtreeIfNeeded()
            XCTAssertEqual(controller.view.bounds.width, 340)
            let bitmap = try XCTUnwrap(controller.view.bitmapImageRepForCachingDisplay(in: controller.view.bounds))
            controller.view.cacheDisplay(in: controller.view.bounds, to: bitmap)
            let dir = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent().appendingPathComponent(".build/guard-qa")
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
            try XCTUnwrap(bitmap.representation(using: .png, properties: [:])).write(to: dir.appendingPathComponent(name + ".png"))
            // Window capture needs the window's display awake; the bitmap above checks layout either way.
            let display = window.screen?.deviceDescription[NSDeviceDescriptionKey("NSScreenNumber")] as? CGDirectDisplayID ?? CGMainDisplayID()
            if CGPreflightScreenCaptureAccess(), CGDisplayIsAsleep(display) == 0 {
                let capture = Process()
                capture.executableURL = URL(fileURLWithPath: "/usr/sbin/screencapture")
                capture.arguments = ["-x", "-o", "-l", String(window.windowNumber), dir.appendingPathComponent(name + "-window.png").path]
                try capture.run(); capture.waitUntilExit()
                XCTAssertEqual(capture.terminationStatus, 0)
            }
            window.orderOut(nil); window.close()
        }
    }
    func testReceiptMatchesExactRequestAndRejectsWrongIdentity() throws {
        let raw = #"{"id":"prompt","session_id":"session","rule_id":"env","verdict":"allow","scope":"session","at":"2026-10-15T12:00:00Z","scope_ids":["permission"]}"#
        let receipt = try JSONDecoder().decode(GuardResolveReceipt.self, from: Data(raw.utf8))
        XCTAssertTrue(receipt.matches(.init(id: "prompt", verdict: "allow", scope: "session")))
        XCTAssertFalse(receipt.matches(.init(id: "other", verdict: "allow", scope: "session")))
        XCTAssertFalse(receipt.matches(.init(id: "prompt", verdict: "deny", scope: "once")))
        XCTAssertFalse(receipt.matches(.init(id: "prompt", verdict: "allow", scope: "session", category: true)), "a kind permission was not recorded")
        let timed = #"{"id":"p","rule_id":"untrusted-egress","verdict":"allow","scope":"exact","expiry":"7d","category":true,"at":"2026-10-15T12:00:00Z"}"#
        let kind = try JSONDecoder().decode(GuardResolveReceipt.self, from: Data(timed.utf8))
        XCTAssertTrue(kind.matches(.init(id: "p", verdict: "allow", scope: "exact", expiry: "7d", category: true)))
        XCTAssertFalse(kind.matches(.init(id: "p", verdict: "allow", scope: "exact", expiry: "24h", category: true)), "a longer grant than asked")
        XCTAssertFalse(kind.matches(.init(id: "p", verdict: "allow", scope: "exact", expiry: "7d")), "a wider grant than asked")
    }

    @MainActor
    func testGuardFeedbackSeparatesSubmittedAndUnconfirmedAnswers() async throws {
        let client = StubDaemonClient()
        let state = AppState(client: client)
        let pending = GuardPending(id: "prompt", agent: "codex", tool: "Read", path: "/fixture", ruleID: "env", ts: "", scopeText: nil, advisor: nil, sessionID: "session")
        state.seedPostureForTesting(nil, pendingGuard: pending)
        client.pending = [pending]
        await state.resolvePendingGuard(verdict: "allow", scope: "once")
        XCTAssertEqual(state.guardResult?.title, "Answer submitted")
        XCTAssertTrue(state.guardResult?.detail.contains("receipt unavailable") == true)
        state.dismissGuardResult()
        XCTAssertNil(state.guardResult)
        client.resolveGuardError = NSError(domain: "fixture", code: 1)
        state.seedPostureForTesting(nil, pendingGuard: pending)
        client.pending = [pending]
        await state.resolvePendingGuard(verdict: "deny", scope: "once")
        XCTAssertEqual(state.guardResult?.title, "Answer not confirmed")
        XCTAssertTrue(state.guardResult?.detail.contains("before deciding again") == true)
    }
}

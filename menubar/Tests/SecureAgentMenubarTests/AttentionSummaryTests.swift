import XCTest
import AppKit
import SwiftUI
import Vision
@testable import SecureAgentMenubar

final class AttentionSummaryTests: XCTestCase {
    private let payload = #"{"state":"attention","needs_you":1,"coverage_count":2,"summary":"Pending request","connected":true,"items":[{"kind":"guard_pending","id":"g","title":"Access request","severity":1}],"attention_summary":{"version":1,"buckets":[{"kind":"decisions","count":1,"coverage_count":0,"first":{"kind":"guard","id":"g","title":"Access request","session_id":"s"}},{"kind":"security","count":0,"coverage_count":0},{"kind":"monitoring","count":0,"coverage_count":2}]}}"#

    func testDecodesCanonicalCategoriesAndExactIdentity() throws {
        let p = try JSONDecoder().decode(PostureModel.self, from: Data(payload.utf8))
        let buckets = try XCTUnwrap(p.validatedAttentionSummary).buckets
        XCTAssertEqual(buckets.map(\.count), [1, 0, 0])
        XCTAssertEqual(buckets.map(\.coverageCount), [0, 0, 2])
        XCTAssertEqual(buckets[0].first?.sessionID, "s")
        XCTAssertEqual(buckets[0].title, "Waiting for your decision")
    }

    func testLegacyAndMalformedOptionalSummaryPreserveTheHeadline() throws {
        for raw in [payload.replacingOccurrences(of: "\"version\":1", with: "\"version\":2"), payload.replacingOccurrences(of: "\"count\":1", with: "\"count\":9"), payload.replacingOccurrences(of: "\"count\":1", with: "\"count\":\"invalid\"")] {
            let p = try JSONDecoder().decode(PostureModel.self, from: Data(raw.utf8))
            XCTAssertNil(p.validatedAttentionSummary)
            XCTAssertEqual(p.needsYou, 1)
            XCTAssertEqual(p.summary, "Pending request")
        }
        let old = PostureModel(state: "attention", needsYou: 1, summary: "Legacy", connected: true)
        XCTAssertNil(old.validatedAttentionSummary)
    }

    @MainActor
    func testCriticalRefreshFailureRetainsUrgencyAndLabelsLastKnownEvidence() async throws {
        let client = StubDaemonClient()
        client.posture = PostureModel(state: "critical", needsYou: 1, summary: "Control outcome unknown.", connected: true)
        let state = AppState(client: client)
        state.seedForTesting(status: client.status)
        await state.lightRefresh(.posture)
        client.postureError = DaemonClientError.transport("unavailable")
        await state.lightRefresh(.posture)
        let hero = ConsoleView(state: state, scrollable: false).heroModel
        XCTAssertEqual(hero.title, "Urgent review")
        XCTAssertTrue(hero.subtitle.contains("Last known observations"))
        XCTAssertTrue(hero.subtitle.contains("Control outcome unknown"))
        client.postureError = nil
        await state.lightRefresh(.posture)
        XCTAssertFalse(ConsoleView(state: state, scrollable: false).heroModel.subtitle.contains("Last known"))
    }

    @MainActor
    private func pumpNativeRunLoop() { RunLoop.main.run(until: Date(timeIntervalSinceNow: 0.05)) }

    @MainActor
    func testNativeOverviewRendersCanonicalCategoriesAtPopoverWidth() async throws {
        _ = NSApplication.shared
        let previous = NSApp.activationPolicy()
        XCTAssertTrue(NSApp.setActivationPolicy(.regular))
        NSApp.finishLaunching()
        defer { NSApp.setActivationPolicy(previous) }
        let state = AppState.previewFlags([])
        state.seedPostureForTesting(try JSONDecoder().decode(PostureModel.self, from: Data(payload.utf8)))
        let view = NSHostingView(rootView: ConsoleView(state: state, scrollable: false).frame(width: 340))
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 340, height: 1100), styleMask: [.titled], backing: .buffered, defer: false)
        window.contentView = view; window.makeKeyAndOrderFront(nil); NSApp.activate(ignoringOtherApps: true)
        defer { window.orderOut(nil); window.contentView = nil }
        try await Task.sleep(for: .milliseconds(200))
        pumpNativeRunLoop(); NSApp.updateWindows(); view.layoutSubtreeIfNeeded(); view.displayIfNeeded()
        let bitmap = try XCTUnwrap(view.bitmapImageRepForCachingDisplay(in: view.bounds))
        view.cacheDisplay(in: view.bounds, to: bitmap)
        // Read the rendered pixels: SwiftUI text is not reliably exposed by
        // the XCTest host's in-process accessibility tree.
        let request = VNRecognizeTextRequest()
        request.recognitionLevel = .accurate
        request.recognitionLanguages = ["en-US"]
        let image = try XCTUnwrap(bitmap.cgImage)
        do {
            try VNImageRequestHandler(cgImage: image, options: [:]).perform([request])
        } catch {
            // A host without on-device text recognition (a CI virtual
            // machine) cannot read the pixels.
            throw XCTSkip("text recognition unavailable on this host: \(error)")
        }
        let text = (request.results ?? []).compactMap { $0.topCandidates(1).first?.string }.joined(separator: " ")
        for label in ["Waiting for your decision: 1 queued", "Security review: 0 queued", "Monitoring problems: 0 queued", "2 monitoring gaps"] { XCTAssertTrue(text.contains(label), text) }
        let root = URL(fileURLWithPath: ".build/attention-qa", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        try XCTUnwrap(bitmap.representation(using: .png, properties: [:])).write(to: root.appendingPathComponent("overview.png"))
    }
}

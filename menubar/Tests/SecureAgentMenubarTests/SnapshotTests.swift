import SwiftUI
import XCTest

@testable import SecureAgentMenubar

final class SnapshotTests: XCTestCase {
    /// Regression guard: the popover renders to a non-empty image from populated
    /// state (catches layout/type regressions in ConsoleView without a daemon).
    /// The preview includes a pending guard decision, so this also exercises the
    /// inline consent card.
    @MainActor
    func testConsoleViewRenders() throws {
        let renderer = ImageRenderer(content: ConsoleView(state: .preview(), scrollable: false))
        renderer.scale = 2.0
        let img = try XCTUnwrap(renderer.nsImage)
        XCTAssertGreaterThan(img.size.width, 0)
        XCTAssertGreaterThan(img.size.height, 0)
    }

    /// The reduced popover must not lose the consent path: a pending guard
    /// surfaces the inline decision card with the plain-language headline.
    @MainActor
    func testPendingGuardHeadlineLanguage() {
        let p = GuardPending(id: "g1", agent: "claude", tool: "Read",
                             path: "/Users/x/.aws/credentials", ruleID: "cloud-creds",
                             ts: "", scopeText: nil)
        XCTAssertEqual(ConsoleView.guardPromptHeadline(p),
                       "Claude wants to read a cloud credential file")
        XCTAssertTrue(ConsoleView.guardPromptDetail(p).contains("credentials"))
    }

    @MainActor
    func testPopoverReductionKeepsGuardVisible() {
        // The preview carries a pendingGuard — its presence is what the inline
        // card keys on. (A nil guard hides the card; nil is the all-clear case.)
        XCTAssertNotNil(AppState.preview().pendingGuard)
    }
}

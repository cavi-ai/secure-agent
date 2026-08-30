import SwiftUI
import XCTest

@testable import SecureAgentMenubar

final class SnapshotTests: XCTestCase {
    /// Regression guard: the popover renders to a non-empty image from populated
    /// state (catches layout/type regressions in ConsoleView without a daemon).
    @MainActor
    func testConsoleViewRenders() throws {
        let renderer = ImageRenderer(content: ConsoleView(state: .preview(), scrollable: false))
        renderer.scale = 2.0
        let img = try XCTUnwrap(renderer.nsImage)
        XCTAssertGreaterThan(img.size.width, 0)
        XCTAssertGreaterThan(img.size.height, 0)
    }
}

import AppKit
import XCTest
@testable import SecureAgentMenubar

@MainActor
final class StatusItemLifecycleTests: XCTestCase {
    func testRepeatedVisibilityLossRestoresOneUsableStatusItem() throws {
        let delegate = AppDelegate()
        let owner = StatusItemController(makeItem: { delegate.makeStatusItem() })
        defer { owner.stop() }
        XCTAssertTrue(owner.start())
        for _ in 0..<3 {
            owner.reconcile()
            let removed = try XCTUnwrap(owner.item)
            removed.isVisible = false
            owner.reconcile()
            let restored = try XCTUnwrap(owner.item)
            XCTAssertFalse(restored === removed)
            XCTAssertTrue(restored.isVisible)
            XCTAssertNotNil(restored.button?.image)
            XCTAssertNotNil(restored.button?.action)
        }
        owner.stop()
        XCTAssertNil(owner.item)
    }

    func testFailedRecoveryDoesNotRepeatedlyCreateStatusItems() throws {
        let delegate = AppDelegate()
        var creations = 0
        let owner = StatusItemController {
            creations += 1
            return creations == 1 ? delegate.makeStatusItem() : nil
        }
        defer { owner.stop() }
        XCTAssertTrue(owner.start())
        try XCTUnwrap(owner.item).isVisible = false
        for _ in 0..<5 { owner.reconcile() }
        XCTAssertEqual(creations, 2, "One loss must cause at most one recovery attempt")
    }

    func testTimerRestoresVisibilityWithoutAStateRefresh() async throws {
        let delegate = AppDelegate()
        let owner = StatusItemController(makeItem: { delegate.makeStatusItem() })
        defer { owner.stop() }
        XCTAssertTrue(owner.start())
        let item = try XCTUnwrap(owner.item)
        item.isVisible = false
        let deadline = ContinuousClock.now + .seconds(7)
        while owner.item === item && ContinuousClock.now < deadline {
            try await Task.sleep(for: .milliseconds(50))
        }
        XCTAssertFalse(owner.item === item, "Recovery must work while daemon state is unchanged")
        XCTAssertTrue(try XCTUnwrap(owner.item).isVisible)
    }

    func testHiddenItemIsReplacedWithAUsableControl() throws {
        let delegate = AppDelegate()
        let owner = StatusItemController(makeItem: { delegate.makeStatusItem() })
        defer { owner.stop() }
        XCTAssertTrue(owner.start())
        let item = try XCTUnwrap(owner.item)
        item.isVisible = false
        owner.reconcile()
        XCTAssertTrue(try XCTUnwrap(owner.item).isVisible)
        XCTAssertFalse(owner.item === item)
    }

}

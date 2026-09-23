import ServiceManagement
import XCTest
@testable import SecureAgentMenubar

/// The file-telemetry card state follows the collector daemon's
/// SMAppService status first, then the spool facts.
final class ESCardStateTests: XCTestCase {
    func testNotFoundMeansRebuild() {
        XCTAssertEqual(esCardState(status: .notFound, tccGranted: false, helperReplaced: false), .notFound)
        XCTAssertEqual(esCardState(status: .notFound, tccGranted: true, helperReplaced: true), .notFound)
    }

    func testNotRegisteredOffersEnable() {
        XCTAssertEqual(esCardState(status: .notRegistered, tccGranted: false, helperReplaced: false), .notRegistered)
        XCTAssertEqual(esCardState(status: .notRegistered, tccGranted: true, helperReplaced: true), .notRegistered,
                       "an old spool must not read as active while nothing is registered")
    }

    func testRequiresApprovalPointsAtLoginItems() {
        XCTAssertEqual(esCardState(status: .requiresApproval, tccGranted: false, helperReplaced: false), .requiresApproval)
        XCTAssertEqual(esCardState(status: .requiresApproval, tccGranted: true, helperReplaced: true), .requiresApproval)
    }

    func testEnabledWithoutGrantAsksForFullDiskAccess() {
        XCTAssertEqual(esCardState(status: .enabled, tccGranted: false, helperReplaced: false), .needsGrant)
    }

    func testEnabledWithReplacedCollectorAsksForRegrant() {
        XCTAssertEqual(esCardState(status: .enabled, tccGranted: false, helperReplaced: true), .needsRegrant)
        XCTAssertEqual(esCardState(status: .enabled, tccGranted: true, helperReplaced: true), .needsRegrant,
                       "a replaced collector outranks an old spool that still has bytes")
    }

    func testEnabledWithGrantIsActive() {
        XCTAssertEqual(esCardState(status: .enabled, tccGranted: true, helperReplaced: false), .active)
    }

    @MainActor func testCopyNamesTheAppNeverTheLaunchdLabel() {
        for stage in ESStage.allCases {
            XCTAssertFalse(stage.title.contains(SetupManager.esCollectorLabel), "\(stage) title")
            XCTAssertFalse(stage.detail.contains(SetupManager.esCollectorLabel), "\(stage) detail")
        }
        XCTAssertFalse(ESStage.grantInstruction.contains(SetupManager.esCollectorLabel))
        XCTAssertTrue(ESStage.grantInstruction.contains("turn on Secure Agent"))
    }

    func testOnlySettingsStepsPoll() {
        XCTAssertEqual(ESStage.allCases.filter(\.awaitsUser), [.requiresApproval, .needsGrant, .needsRegrant])
    }
}

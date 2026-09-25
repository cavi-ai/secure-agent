import ServiceManagement
import XCTest
@testable import SecureAgentMenubar

/// The file-telemetry card state follows the collector daemon's
/// SMAppService status first, then the spool facts.
final class ESCardStateTests: XCTestCase {
    func testNotFoundWithPlistInTheBundleMeansNotRegisteredYet() {
        XCTAssertEqual(esCardState(status: .notFound, plistPresent: true, tccGranted: false, helperReplaced: false), .notRegistered)
        XCTAssertEqual(esCardState(status: .notFound, plistPresent: true, tccGranted: true, helperReplaced: true), .notRegistered,
                       "an old spool must not read as active while nothing is registered")
    }

    func testNotFoundWithoutPlistMeansRebuild() {
        XCTAssertEqual(esCardState(status: .notFound, plistPresent: false, tccGranted: false, helperReplaced: false), .notFound)
        XCTAssertEqual(esCardState(status: .notFound, plistPresent: false, tccGranted: true, helperReplaced: true), .notFound)
    }

    /// Every status × plistPresent × spool facts.
    func testStatusTimesPlistPresentTable() {
        let rows: [(SMAppService.Status, Bool, Bool, Bool, ESStage)] = [
            // status, plistPresent, tccGranted, helperReplaced -> stage
            (.notFound, true, false, false, .notRegistered),
            (.notFound, false, false, false, .notFound),
            (.notRegistered, true, false, false, .notRegistered),
            (.notRegistered, false, false, false, .notRegistered),
            (.notRegistered, true, true, true, .notRegistered),
            (.requiresApproval, true, false, false, .requiresApproval),
            (.requiresApproval, false, true, true, .requiresApproval),
            (.enabled, true, false, false, .needsGrant),
            (.enabled, false, false, false, .needsGrant),
            (.enabled, true, false, true, .needsRegrant),
            (.enabled, true, true, true, .needsRegrant),
            (.enabled, true, true, false, .active),
            (.enabled, false, true, false, .active),
        ]
        for (status, plist, granted, replaced, want) in rows {
            XCTAssertEqual(esCardState(status: status, plistPresent: plist, tccGranted: granted, helperReplaced: replaced), want,
                           "status \(status.rawValue) plist \(plist) granted \(granted) replaced \(replaced)")
        }
    }

    func testRequiresApprovalPointsAtLoginItems() {
        XCTAssertEqual(esCardState(status: .requiresApproval, plistPresent: true, tccGranted: false, helperReplaced: false), .requiresApproval)
        XCTAssertEqual(esCardState(status: .requiresApproval, plistPresent: true, tccGranted: true, helperReplaced: true), .requiresApproval)
    }

    func testEnabledWithoutGrantAsksForFullDiskAccess() {
        XCTAssertEqual(esCardState(status: .enabled, plistPresent: true, tccGranted: false, helperReplaced: false), .needsGrant)
    }

    func testEnabledWithReplacedCollectorAsksForRegrant() {
        XCTAssertEqual(esCardState(status: .enabled, plistPresent: true, tccGranted: false, helperReplaced: true), .needsRegrant)
        XCTAssertEqual(esCardState(status: .enabled, plistPresent: true, tccGranted: true, helperReplaced: true), .needsRegrant,
                       "a replaced collector outranks an old spool that still has bytes")
    }

    func testEnabledWithGrantIsActive() {
        XCTAssertEqual(esCardState(status: .enabled, plistPresent: true, tccGranted: true, helperReplaced: false), .active)
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

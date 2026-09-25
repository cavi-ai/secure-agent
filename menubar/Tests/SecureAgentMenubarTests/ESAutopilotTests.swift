import ServiceManagement
import XCTest
@testable import SecureAgentMenubar

/// The file-telemetry autopilot: register once per launch, open each System
/// Settings pane once per build, and never act after the user's Remove.
final class ESAutopilotTests: XCTestCase {
    func testDecisionTable() {
        let rows: [(ESStage, Bool, Bool, Set<ESSettingsPane>, ESAutopilotAction)] = [
            // stage, userDisabled, attemptedThisLaunch, panesOpenedForBuild -> action
            (.notRegistered, false, false, [], .register),
            (.notRegistered, false, true, [], .none),
            (.notRegistered, false, false, [.loginItems, .fullDiskAccess], .register),
            (.requiresApproval, false, false, [], .open(.loginItems)),
            (.requiresApproval, false, true, [], .open(.loginItems)),
            (.requiresApproval, false, false, [.fullDiskAccess], .open(.loginItems)),
            (.requiresApproval, false, false, [.loginItems], .none),
            (.needsGrant, false, false, [], .open(.fullDiskAccess)),
            (.needsGrant, false, true, [.loginItems], .open(.fullDiskAccess)),
            (.needsGrant, false, false, [.fullDiskAccess], .none),
            (.needsRegrant, false, false, [], .open(.fullDiskAccess)),
            (.needsRegrant, false, false, [.loginItems, .fullDiskAccess], .none),
            (.legacyInstalled, false, false, [], .none),
            (.notFound, false, false, [], .none),
            (.active, false, false, [], .none),
        ]
        for (stage, disabled, attempted, panes, want) in rows {
            XCTAssertEqual(ESAutopilot.decide(stage: stage, userDisabled: disabled,
                                              attemptedThisLaunch: attempted, panesOpenedForBuild: panes),
                           want, "\(stage) disabled \(disabled) attempted \(attempted) panes \(panes)")
        }
    }

    func testUserDisabledSuppressesEveryAction() {
        let paneSets: [Set<ESSettingsPane>] = [[], [.loginItems], [.fullDiskAccess], [.loginItems, .fullDiskAccess]]
        for stage in ESStage.allCases {
            for attempted in [false, true] {
                for panes in paneSets {
                    XCTAssertEqual(ESAutopilot.decide(stage: stage, userDisabled: true,
                                                      attemptedThisLaunch: attempted, panesOpenedForBuild: panes),
                                   .none, "\(stage)")
                }
            }
        }
    }

    func testPanesOpenedAreRememberedPerBuild() throws {
        let defaults = try XCTUnwrap(UserDefaults(suiteName: "ESAutopilotTests.\(UUID().uuidString)"))
        let build241 = ESAutopilotMemory(defaults: defaults, build: "241")
        XCTAssertEqual(build241.panesOpenedForBuild, [])
        build241.markOpened(.loginItems)
        XCTAssertEqual(build241.panesOpenedForBuild, [.loginItems])
        XCTAssertEqual(ESAutopilotMemory(defaults: defaults, build: "242").panesOpenedForBuild, [],
                       "a new build opens the panes again")
    }

    @MainActor func testRemoveSetsUserDisabledAndSuppressesRegistration() throws {
        try XCTSkipIf(FileManager.default.fileExists(atPath: SetupManager.legacyESPlistPath),
                      "an old helper on this Mac makes the stage legacyInstalled")
        let service = FakeESService()
        let defaults = try XCTUnwrap(UserDefaults(suiteName: "ESAutopilotTests.\(UUID().uuidString)"))
        var opened: [ESSettingsPane] = []
        let setup = SetupManager(esService: service, defaults: defaults,
                                 plistPresent: { true }, openPane: { opened.append($0) })

        setup.refreshESState()
        XCTAssertEqual(service.registerCount, 1, "launch registers a never-registered service")
        XCTAssertEqual(opened, [.loginItems], "then opens Login Items once")
        setup.refreshESState()
        XCTAssertEqual(service.registerCount, 1, "no second registration this launch")
        XCTAssertEqual(opened, [.loginItems], "no second pane for this build")

        try setup.removeESCollector()
        XCTAssertTrue(setup.esUserDisabled)
        XCTAssertEqual(service.unregisterCount, 1)

        let relaunch = SetupManager(esService: service, defaults: defaults,
                                    plistPresent: { true }, openPane: { opened.append($0) })
        relaunch.refreshESState()
        XCTAssertEqual(service.registerCount, 1, "after Remove, a new launch does not register")

        try relaunch.installESCollector()
        XCTAssertFalse(relaunch.esUserDisabled, "Enable clears the Remove")
        XCTAssertEqual(service.registerCount, 2)
        try relaunch.removeESCollector()
    }

    @MainActor func testFailedRegistrationIsRecordedAndNotRetriedThisLaunch() throws {
        try XCTSkipIf(FileManager.default.fileExists(atPath: SetupManager.legacyESPlistPath),
                      "an old helper on this Mac makes the stage legacyInstalled")
        let service = FakeESService()
        service.registerError = NSError(domain: "SMAppServiceErrorDomain", code: 1,
                                        userInfo: [NSLocalizedDescriptionKey: "Operation not permitted"])
        let defaults = try XCTUnwrap(UserDefaults(suiteName: "ESAutopilotTests.\(UUID().uuidString)"))
        let setup = SetupManager(esService: service, defaults: defaults,
                                 plistPresent: { true }, openPane: { _ in })
        setup.refreshESState()
        setup.refreshESState()
        XCTAssertEqual(service.registerCount, 1)
        XCTAssertEqual(setup.lastError, "file telemetry: Operation not permitted")
    }
}

/// Stands in for SMAppService: register moves to requiresApproval, as a
/// first registration does on macOS.
final class FakeESService: ESServiceControl {
    var status: SMAppService.Status = .notFound
    var registerCount = 0
    var unregisterCount = 0
    var registerError: Error?

    func register() throws {
        registerCount += 1
        if let registerError { throw registerError }
        status = .requiresApproval
    }

    func unregister() throws {
        unregisterCount += 1
        status = .notRegistered
    }
}

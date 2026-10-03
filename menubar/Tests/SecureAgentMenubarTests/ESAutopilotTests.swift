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
            (.wrongLocation, false, false, [], .none),
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
                                 plistPresent: { true }, openPane: { opened.append($0) },
                                 appURL: installedCopy)

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
                                    plistPresent: { true }, openPane: { opened.append($0) },
                                 appURL: installedCopy)
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
                                 plistPresent: { true }, openPane: { _ in }, appURL: installedCopy)
        setup.refreshESState()
        setup.refreshESState()
        XCTAssertEqual(service.registerCount, 1)
        XCTAssertEqual(setup.lastError, "file telemetry: Operation not permitted")
    }

    func testReregisterOnlyAnEnabledJobLaunchdRefusesToSpawn() {
        let refused = LaunchdProbe.loaded(state: "spawn scheduled", pid: nil, lastExitCode: "78: EX_CONFIG")
        let rows: [(SMAppService.Status, Bool, Bool, LaunchdProbe, Bool, String)] = [
            // status, userDisabled, attemptedThisLaunch, launchd job -> re-register
            (.enabled, false, false, refused, true, "enabled, not removed, launchd refuses the job"),
            (.enabled, false, true, refused, false, "already attempted this launch"),
            (.enabled, true, false, refused, false, "removed by the user"),
            (.enabled, false, false, .loaded(state: "running", pid: 412, lastExitCode: "78: EX_CONFIG"), false, "running job"),
            (.enabled, false, false, .loaded(state: "spawn scheduled", pid: nil, lastExitCode: "1"), false, "other exit code"),
            (.enabled, false, false, .loaded(state: "waiting", pid: nil, lastExitCode: "(never exited)"), false, "never exited"),
            (.requiresApproval, false, false, refused, false, "not enabled"),
            (.enabled, false, false, .notFound, false, "no job"),
            (.enabled, false, false, .unreadable, false, "unreadable job"),
        ]
        for (status, disabled, attempted, job, want, why) in rows {
            XCTAssertEqual(ESAutopilot.needsReregister(serviceStatus: status, userDisabled: disabled,
                                                       attemptedThisLaunch: attempted, launchd: job), want, why)
        }
    }

    func testOnlyTheExactRepairURLTriggers() throws {
        XCTAssertTrue(ESAutopilot.isRepairURL(try XCTUnwrap(URL(string: "secure-agent://telemetry/repair"))))
        let others = ["secure-agent://telemetry/repair/", "secure-agent://telemetry/repair?now=1",
                      "secure-agent://telemetry/repair#x", "secure-agent://telemetry", "secure-agent://telemetry/repairs",
                      "secure-agent://other/repair", "secure-agent://user@telemetry/repair",
                      "https://telemetry/repair", "secure-agent:telemetry/repair"]
        for other in others {
            XCTAssertFalse(ESAutopilot.isRepairURL(try XCTUnwrap(URL(string: other))), other)
        }
    }

    @MainActor func testRefreshReregistersAJobLaunchdRefusesOncePerLaunch() async throws {
        try XCTSkipIf(FileManager.default.fileExists(atPath: SetupManager.legacyESPlistPath),
                      "an old helper on this Mac makes the stage legacyInstalled")
        let service = FakeESService()
        service.status = .enabled
        let defaults = try XCTUnwrap(UserDefaults(suiteName: "ESAutopilotTests.\(UUID().uuidString)"))
        let setup = SetupManager(esService: service, defaults: defaults, plistPresent: { true }, openPane: { _ in },
                                 launchdProbe: { .loaded(state: "spawn scheduled", pid: nil, lastExitCode: "78: EX_CONFIG") },
                                 appURL: installedCopy)

        setup.refreshESState()
        let probe = try XCTUnwrap(setup.esRepairProbe, "an enabled service's job is probed")
        await probe.value
        XCTAssertEqual(service.unregisterCount, 1, "unregisters the stuck registration")
        XCTAssertEqual(service.registerCount, 1, "and registers again")

        setup.refreshESState()
        XCTAssertNil(setup.esRepairProbe, "no second probe this launch")
        XCTAssertEqual(service.registerCount, 1)

        setup.reregisterESService()
        XCTAssertEqual(service.unregisterCount, 2, "the repair URL's path ignores this launch's attempt")
        XCTAssertEqual(service.registerCount, 2)
    }

    @MainActor func testACopyOutsideApplicationsNeverRegistersOrRepairsTheHelper() throws {
        let service = FakeESService()
        service.status = .enabled
        let defaults = try XCTUnwrap(UserDefaults(suiteName: "ESAutopilotTests.\(UUID().uuidString)"))
        var opened: [ESSettingsPane] = []
        let setup = SetupManager(esService: service, defaults: defaults, plistPresent: { true },
                                 openPane: { opened.append($0) },
                                 launchdProbe: { .loaded(state: "spawn scheduled", pid: nil, lastExitCode: "78: EX_CONFIG") },
                                 appURL: URL(fileURLWithPath: "/Users/dev/secure-agent/dist/Secure Agent.app"))

        setup.refreshESState()
        XCTAssertEqual(setup.esStage, .wrongLocation)
        XCTAssertNil(setup.esRepairProbe, "no launchd probe, no repair")
        setup.reregisterESService()
        XCTAssertEqual(setup.lastError, AppIdentity.wrongLocationMessage)
        XCTAssertThrowsError(try setup.installESCollector())
        XCTAssertEqual(service.registerCount, 0)
        XCTAssertEqual(service.unregisterCount, 0)
        XCTAssertEqual(opened, [])
    }

    @MainActor func testRefreshLeavesARunningJobAlone() async throws {
        try XCTSkipIf(FileManager.default.fileExists(atPath: SetupManager.legacyESPlistPath),
                      "an old helper on this Mac makes the stage legacyInstalled")
        let service = FakeESService()
        service.status = .enabled
        let defaults = try XCTUnwrap(UserDefaults(suiteName: "ESAutopilotTests.\(UUID().uuidString)"))
        let setup = SetupManager(esService: service, defaults: defaults, plistPresent: { true }, openPane: { _ in },
                                 launchdProbe: { .loaded(state: "running", pid: 412, lastExitCode: nil) },
                                 appURL: installedCopy)

        setup.refreshESState()
        let probe = try XCTUnwrap(setup.esRepairProbe)
        await probe.value
        XCTAssertEqual(service.unregisterCount, 0)
        XCTAssertEqual(service.registerCount, 0)
    }
}

private let installedCopy = URL(fileURLWithPath: AppIdentity.installedAppPath)

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

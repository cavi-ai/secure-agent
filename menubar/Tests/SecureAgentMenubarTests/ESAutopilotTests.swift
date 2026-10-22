import ServiceManagement
import XCTest
@testable import SecureAgentMenubar

/// The file-telemetry autopilot: register once per launch, open each System
/// Settings pane once per build, and never act after the user's Remove.
final class ESAutopilotTests: XCTestCase {
    private func temporaryHome() -> String {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        addTeardownBlock { try? FileManager.default.removeItem(at: url) }
        return url.path
    }

    @MainActor func testTelemetryChoiceReachesDaemonConfiguration() throws {
        let home = temporaryHome()
        let defaults = try XCTUnwrap(UserDefaults(suiteName: UUID().uuidString))
        let setup = SetupManager(esService: FakeESService(), defaults: defaults, configurationHome: home,
                                 plistPresent: { true }, openPane: { _ in }, appURL: installedCopy)
        try setup.removeESCollector()
        XCTAssertEqual(try ConfigStore(home: home).document().scalar("file_telemetry_enabled")?.text, "false")
        try setup.installESCollector()
        XCTAssertEqual(try ConfigStore(home: home).document().scalar("file_telemetry_enabled")?.text, "true")
    }

    @MainActor func testTelemetryMigrationPreservesExplicitConfig() throws {
        let home = temporaryHome()
        let defaults = try XCTUnwrap(UserDefaults(suiteName: UUID().uuidString))
        defaults.set(true, forKey: ESAutopilotMemory.userDisabledKey)
        let setup = SetupManager(esService: FakeESService(), defaults: defaults, configurationHome: home,
                                 plistPresent: { true }, openPane: { _ in }, appURL: installedCopy)
        setup.migrateTelemetryChoice()
        XCTAssertEqual(try ConfigStore(home: home).document().scalar("file_telemetry_enabled")?.text, "false")
        try ConfigStore(home: home).update { try ConfigDocument($0).setting("file_telemetry_enabled", to: true).text }
        setup.migrateTelemetryChoice()
        XCTAssertEqual(try ConfigStore(home: home).document().scalar("file_telemetry_enabled")?.text, "true")
    }

    @MainActor func testConfigOptOutPreventsAutomaticRegistrationAndRepair() throws {
        let home = temporaryHome()
        try ConfigStore(home: home).update { try ConfigDocument($0).setting("file_telemetry_enabled", to: false).text }
        let service = FakeESService()
        let defaults = try XCTUnwrap(UserDefaults(suiteName: UUID().uuidString))
        let setup = SetupManager(esService: service, defaults: defaults, configurationHome: home,
                                 plistPresent: { true }, openPane: { _ in }, appURL: installedCopy)
        setup.refreshESState()
        XCTAssertTrue(setup.esUserDisabled)
        XCTAssertEqual(service.registerCount, 0)
        service.status = .enabled
        setup.refreshESState()
        XCTAssertNil(setup.esRepairProbe)
        XCTAssertEqual(service.unregisterCount, 0)
    }

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
        let setup = SetupManager(esService: service, defaults: defaults, configurationHome: temporaryHome(),
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

        let relaunch = SetupManager(esService: service, defaults: defaults, configurationHome: temporaryHome(),
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
        let setup = SetupManager(esService: service, defaults: defaults, configurationHome: temporaryHome(),
                                 plistPresent: { true }, openPane: { _ in }, appURL: installedCopy)
        setup.refreshESState()
        setup.refreshESState()
        XCTAssertEqual(service.registerCount, 1)
        XCTAssertEqual(setup.lastError, "file telemetry: Operation not permitted")
    }

    func testReregisterOnlyAnEnabledJobLaunchdRefusesToSpawn() {
        let refused = LaunchdProbe.loaded(state: "spawn scheduled", pid: nil, lastExitCode: "78: EX_CONFIG")
        let running = LaunchdProbe.loaded(state: "running", pid: 412, lastExitCode: "(never exited)")
        let rows: [(SMAppService.Status, Bool, Bool, LaunchdProbe, Bool, Bool, String)] = [
            // status, userDisabled, attemptedThisLaunch, launchd job, helper stale -> re-register
            (.enabled, false, false, refused, false, true, "enabled, not removed, launchd refuses the job"),
            (.enabled, false, true, refused, false, false, "already attempted this launch"),
            (.enabled, true, false, refused, false, false, "removed by the user"),
            (.enabled, false, false, .loaded(state: "running", pid: 412, lastExitCode: "78: EX_CONFIG"), false, false, "running job"),
            (.enabled, false, false, .loaded(state: "spawn scheduled", pid: nil, lastExitCode: "1"), false, false, "other exit code"),
            (.enabled, false, false, .loaded(state: "waiting", pid: nil, lastExitCode: "(never exited)"), false, false, "never exited"),
            (.requiresApproval, false, false, refused, false, false, "not enabled"),
            (.enabled, false, false, .notFound, false, true, "enabled with no job: the app bundle was replaced in place"),
            (.enabled, false, true, .notFound, false, true, "no job after this launch's own attempt: retried"),
            (.enabled, true, false, .notFound, false, false, "no job, removed by the user"),
            (.requiresApproval, false, false, .notFound, false, false, "no job, not enabled"),
            (.enabled, false, false, .unreadable, false, false, "unreadable job"),
            (.enabled, false, false, running, true, true, "running process predates the helper on disk"),
            (.enabled, false, true, running, true, false, "stale, already attempted this launch"),
            (.enabled, true, false, running, true, false, "stale, removed by the user"),
            (.requiresApproval, false, false, running, true, false, "stale, not enabled"),
        ]
        for (status, disabled, attempted, job, stale, want, why) in rows {
            XCTAssertEqual(ESAutopilot.needsReregister(serviceStatus: status, userDisabled: disabled,
                                                       attemptedThisLaunch: attempted, launchd: job,
                                                       helperStale: stale), want, why)
        }
        XCTAssertFalse(ESAutopilot.needsReregister(serviceStatus: .enabled, userDisabled: false, attemptedThisLaunch: true,
                                                   launchd: .notFound, helperStale: false,
                                                   missingJobRepairs: ESAutopilot.maxMissingJobRepairs),
                       "a missing job is re-registered a bounded number of times a launch")
    }

    /// An app replaced in place leaves the service enabled with no launchd
    /// job, and the launch's own re-register of the old helper can leave it
    /// that way: the repair keeps re-registering while the job stays missing,
    /// up to its bound, and leaves a loaded job alone.
    @MainActor func testRefreshReregistersAMissingJobUntilLaunchdHoldsIt() async throws {
        try XCTSkipIf(FileManager.default.fileExists(atPath: SetupManager.legacyESPlistPath),
                      "an old helper on this Mac makes the stage legacyInstalled")
        let service = FakeESService()
        service.status = .enabled
        service.registerStatus = .enabled
        let job = JobBox(.notFound)
        let defaults = try XCTUnwrap(UserDefaults(suiteName: "ESAutopilotTests.\(UUID().uuidString)"))
        let setup = SetupManager(esService: service, defaults: defaults, configurationHome: temporaryHome(), plistPresent: { true }, openPane: { _ in },
                                 launchdProbe: { job.value }, helperStaleProbe: { _ in false },
                                 appURL: installedCopy)
        setup.esRepairProbeInterval = 0
        let probeOnce = { () async in
            setup.refreshESState()
            if let probe = setup.esRepairProbe { await probe.value }
        }

        await probeOnce()
        await probeOnce()
        XCTAssertEqual(service.registerCount, 2, "re-registered on each probe that finds no job")

        job.value = .loaded(state: "running", pid: 600, lastExitCode: nil)
        await probeOnce()
        XCTAssertEqual(service.registerCount, 2, "a loaded job is left alone")

        job.value = .notFound
        for _ in 0..<5 { await probeOnce() }
        XCTAssertEqual(service.registerCount, ESAutopilot.maxMissingJobRepairs, "bounded per launch")
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
        let setup = SetupManager(esService: service, defaults: defaults, configurationHome: temporaryHome(), plistPresent: { true }, openPane: { _ in },
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

        await setup.reregisterESService()
        XCTAssertEqual(service.unregisterCount, 2, "the repair URL's path ignores this launch's attempt")
        XCTAssertEqual(service.registerCount, 2)
    }

    @MainActor func testACopyOutsideApplicationsNeverRegistersOrRepairsTheHelper() async throws {
        let service = FakeESService()
        service.status = .enabled
        let defaults = try XCTUnwrap(UserDefaults(suiteName: "ESAutopilotTests.\(UUID().uuidString)"))
        var opened: [ESSettingsPane] = []
        let setup = SetupManager(esService: service, defaults: defaults, configurationHome: temporaryHome(), plistPresent: { true },
                                 openPane: { opened.append($0) },
                                 launchdProbe: { .loaded(state: "spawn scheduled", pid: nil, lastExitCode: "78: EX_CONFIG") },
                                 appURL: URL(fileURLWithPath: "/Users/dev/secure-agent/dist/Secure Agent.app"))

        setup.refreshESState()
        XCTAssertEqual(setup.esStage, .wrongLocation)
        XCTAssertNil(setup.esRepairProbe, "no launchd probe, no repair")
        await setup.reregisterESService()
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
        let setup = SetupManager(esService: service, defaults: defaults, configurationHome: temporaryHome(), plistPresent: { true }, openPane: { _ in },
                                 launchdProbe: { .loaded(state: "running", pid: 412, lastExitCode: nil) },
                                 helperStaleProbe: { _ in false },
                                 appURL: installedCopy)

        setup.refreshESState()
        let probe = try XCTUnwrap(setup.esRepairProbe)
        await probe.value
        XCTAssertEqual(service.unregisterCount, 0)
        XCTAssertEqual(service.registerCount, 0)
    }

    /// A running collector older than the helper on disk is restarted once:
    /// macOS refuses it file events whatever Full Disk Access says.
    @MainActor func testRefreshRestartsARunningJobOlderThanItsHelperOncePerLaunch() async throws {
        try XCTSkipIf(FileManager.default.fileExists(atPath: SetupManager.legacyESPlistPath),
                      "an old helper on this Mac makes the stage legacyInstalled")
        let service = FakeESService()
        service.status = .enabled
        let defaults = try XCTUnwrap(UserDefaults(suiteName: "ESAutopilotTests.\(UUID().uuidString)"))
        let running = LaunchdProbe.loaded(state: "running", pid: 577, lastExitCode: "(never exited)")
        let setup = SetupManager(esService: service, defaults: defaults, configurationHome: temporaryHome(), plistPresent: { true }, openPane: { _ in },
                                 launchdProbe: { running },
                                 helperStaleProbe: { $0 == running },
                                 appURL: installedCopy)

        setup.refreshESState()
        let probe = try XCTUnwrap(setup.esRepairProbe, "an enabled service's job is probed")
        await probe.value
        XCTAssertEqual(service.unregisterCount, 1, "unregisters the stale job")
        XCTAssertEqual(service.registerCount, 1, "and registers it again from this build")

        setup.refreshESState()
        XCTAssertNil(setup.esRepairProbe, "no second probe this launch")
        XCTAssertEqual(service.registerCount, 1)
    }

    /// macOS applies the unregister of a running job after the call returns;
    /// the repair registers only once it has, or the helper is left unregistered.
    @MainActor func testReregisterWaitsForTheUnregisterToApply() async throws {
        let service = FakeESService()
        service.status = .enabled
        service.unregisterLag = 3
        let defaults = try XCTUnwrap(UserDefaults(suiteName: "ESAutopilotTests.\(UUID().uuidString)"))
        let setup = SetupManager(esService: service, defaults: defaults, configurationHome: temporaryHome(), plistPresent: { true }, openPane: { _ in },
                                 launchdProbe: { .notFound }, helperStaleProbe: { _ in false },
                                 appURL: installedCopy)

        await setup.reregisterESService()
        XCTAssertNil(setup.lastError)
        XCTAssertEqual(service.unregisterCount, 1)
        XCTAssertEqual(service.registerCount, 1, "one register, after the unregister applied")
        XCTAssertEqual(service.status, .requiresApproval)
    }
}

private let installedCopy = URL(fileURLWithPath: AppIdentity.installedAppPath)

/// The launchd job a test's probe reports; the probe reads it off the main actor.
final class JobBox: @unchecked Sendable {
    private let lock = NSLock()
    private var job: LaunchdProbe
    init(_ job: LaunchdProbe) { self.job = job }
    var value: LaunchdProbe {
        get { lock.lock(); defer { lock.unlock() }; return job }
        set { lock.lock(); job = newValue; lock.unlock() }
    }
}

/// Stands in for SMAppService: register moves to requiresApproval, as a
/// first registration does on macOS.
final class FakeESService: ESServiceControl {
    var registerCount = 0
    var unregisterCount = 0
    var registerError: Error?
    /// The status a register leaves: an approved service stays `.enabled`.
    var registerStatus: SMAppService.Status = .requiresApproval
    /// Reads of `status` that still answer `.enabled` after an unregister, as
    /// macOS applies it late; a register before they run out fails.
    var unregisterLag = 0
    private var lagLeft = 0
    private var stored: SMAppService.Status = .notFound

    var status: SMAppService.Status {
        get {
            guard lagLeft == 0 else {
                lagLeft -= 1
                return .enabled
            }
            return stored
        }
        set { stored = newValue }
    }

    func register() throws {
        registerCount += 1
        if lagLeft > 0 { throw NSError(domain: "SMAppServiceErrorDomain", code: 1) }
        if let registerError { throw registerError }
        stored = registerStatus
    }

    func unregister() throws {
        unregisterCount += 1
        stored = .notRegistered
        lagLeft = unregisterLag
    }
}

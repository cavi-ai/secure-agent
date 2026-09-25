import ServiceManagement
import XCTest
@testable import SecureAgentMenubar

/// The Telemetry Doctor: fixture parsers, the evaluate table, and the spool
/// set-aside fix.
final class TelemetryDoctorTests: XCTestCase {
    private let now = Date(timeIntervalSince1970: 1_790_000_000)

    // MARK: Fixtures

    static let codesignTeamHelper = """
    Executable=/Applications/Secure Agent.app/Contents/MacOS/secure-agent-esd
    Identifier=com.cavi-ai.secure-agent-esd
    Format=Mach-O universal (x86_64 arm64)
    CodeDirectory v=20500 size=29608 flags=0x10000(runtime) hashes=919+2 location=embedded
    Signature size=4791
    Signed Time=Sep 25, 2026 at 5:57:32 PM
    Info.plist=not bound
    TeamIdentifier=ABCDE12345
    Runtime Version=12.0.0
    Sealed Resources=none
    Internal requirements count=1 size=196
    """

    static let codesignAdhocApp = """
    Executable=/Applications/Secure Agent.app/Contents/MacOS/SecureAgent
    Identifier=com.cavi-ai.secure-agent
    Format=app bundle with Mach-O thin (arm64)
    CodeDirectory v=20400 size=8676 flags=0x20002(adhoc,linker-signed) hashes=264+3 location=embedded
    Signature=adhoc
    Info.plist entries=11
    TeamIdentifier=not set
    Sealed Resources version=2 rules=13 files=9
    Internal requirements count=0 size=12
    """

    static let codesignUnsigned = "/Applications/Secure Agent.app/Contents/MacOS/secure-agent-esd: code object is not signed at all\n"

    static let launchctlLoaded = """
    system/com.cavi-ai.secure-agent-esd = {
    \tactive count = 1
    \tpath = /Applications/Secure Agent.app/Contents/Library/LaunchDaemons/com.cavi-ai.secure-agent-esd.plist
    \ttype = LaunchDaemon
    \tstate = running

    \tprogram identifier = Contents/MacOS/secure-agent-esd (mode: 2)
    \tparent bundle identifier = com.cavi-ai.secure-agent
    \tdefault environment = {
    \t\tPATH => /usr/bin:/bin:/usr/sbin:/sbin
    \t}

    \tdomain = system
    \truns = 1
    \tpid = 812
    \timmediate reason = speculative
    \tlast exit code = (never exited)
    \tendpoints = {
    \t\tstate = active
    \t\tpid = 1
    \t}
    }
    """

    static let launchctlNotRunning = """
    system/com.cavi-ai.secure-agent-esd = {
    \tactive count = 0
    \tstate = not running
    \truns = 4
    \tlast exit code = 78: EX_CONFIG
    }
    """

    static let launchctlNotFound = """
    Bad request.
    Could not find service "com.cavi-ai.secure-agent-esd" in domain for system
    """

    // MARK: Parsers

    func testCodesignParsesTeamSignedHelper() {
        XCTAssertEqual(CodeSignature.parse(Self.codesignTeamHelper),
                       CodeSignature(identifier: "com.cavi-ai.secure-agent-esd", adhoc: false, teamIdentifier: "ABCDE12345"))
    }

    func testCodesignParsesAdhocApp() {
        XCTAssertEqual(CodeSignature.parse(Self.codesignAdhocApp),
                       CodeSignature(identifier: "com.cavi-ai.secure-agent", adhoc: true, teamIdentifier: nil))
    }

    func testCodesignUnsignedIsNil() {
        XCTAssertNil(CodeSignature.parse(Self.codesignUnsigned))
        XCTAssertNil(CodeSignature.parse(""))
    }

    func testLaunchctlLoadedWithPid() {
        XCTAssertEqual(LaunchdProbe.parse(Self.launchctlLoaded),
                       .loaded(state: "running", pid: 812, lastExitCode: "(never exited)"),
                       "nested endpoint keys must not override the top-level state and pid")
    }

    func testLaunchctlLoadedWithoutPid() {
        XCTAssertEqual(LaunchdProbe.parse(Self.launchctlNotRunning),
                       .loaded(state: "not running", pid: nil, lastExitCode: "78: EX_CONFIG"))
    }

    func testLaunchctlCouldNotFindService() {
        XCTAssertEqual(LaunchdProbe.parse(Self.launchctlNotFound), .notFound)
        XCTAssertEqual(LaunchdProbe.parse(""), .unreadable)
    }

    func testSpoolMtimeDecodesRFC3339AndGoZeroTime() {
        XCTAssertEqual(ESServiceSnapshotModel(state: "running", spoolMtime: "2026-09-23T10:00:00.123456789-07:00")
                        .spoolMtimeDate.map { Int($0.timeIntervalSince1970) }, 1_790_182_800)
        XCTAssertEqual(ESServiceSnapshotModel(state: "running", spoolMtime: "2026-09-23T17:00:00Z")
                        .spoolMtimeDate.map { Int($0.timeIntervalSince1970) }, 1_790_182_800)
        XCTAssertNil(ESServiceSnapshotModel(state: "not-loaded", spoolMtime: "0001-01-01T00:00:00Z").spoolMtimeDate)
    }

    func testStatusDecodesESService() throws {
        let body = #"{"running":true,"uptime":"1m","active_agents":0,"es_service":{"state":"not-loaded","spool_size":11534336,"spool_mtime":"2026-09-23T17:00:00Z","helper_mtime":"0001-01-01T00:00:00Z","flooding":true,"unparsed_share":0.9998,"bytes_skipped":0}}"#
        let status = try JSONDecoder().decode(StatusResponse.self, from: Data(body.utf8))
        XCTAssertEqual(status.esService?.state, "not-loaded")
        XCTAssertEqual(status.esService?.flooding, true)
        XCTAssertEqual(status.esService?.unparsedShare ?? 0, 0.9998, accuracy: 1e-9)
    }

    // MARK: Evaluate

    private func iso(_ date: Date) -> String { ISO8601DateFormatter().string(from: date) }

    /// A healthy, active install; each scenario changes what it needs.
    private func facts(_ change: (inout TelemetryFacts) -> Void = { _ in }) -> TelemetryFacts {
        var f = TelemetryFacts(
            now: now,
            appSignature: CodeSignature(identifier: "com.cavi-ai.secure-agent", adhoc: false, teamIdentifier: "ABCDE12345"),
            helperSignature: CodeSignature(identifier: "com.cavi-ai.secure-agent-esd", adhoc: false, teamIdentifier: "ABCDE12345"),
            plistPresent: true,
            serviceStatus: .enabled,
            launchd: .loaded(state: "running", pid: 812, lastExitCode: "(never exited)"),
            helperLogLastLine: "es-collector: eslogger started (pid 813), spool /var/db/secure-agent/es-spool.jsonl",
            spoolMtime: now.addingTimeInterval(-5),
            esService: ESServiceSnapshotModel(state: "running", spoolSize: 4096, spoolMtime: iso(now.addingTimeInterval(-5)),
                                              flooding: false, unparsedShare: 0.01),
            legacyInstalled: false,
            daemonChecks: [DaemonDoctorCheckModel(id: "hooks", title: "Hooks", state: "pass")])
        change(&f)
        return f
    }

    private func check(_ checks: [DoctorCheck], _ id: String, file: StaticString = #filePath, line: UInt = #line) -> DoctorCheck? {
        let found = checks.first { $0.id == id }
        XCTAssertNotNil(found, "no check \(id)", file: file, line: line)
        return found
    }

    private func assertCheck(_ checks: [DoctorCheck], _ id: String, _ state: DoctorState, _ fix: DoctorFix?,
                             file: StaticString = #filePath, line: UInt = #line) {
        guard let c = check(checks, id, file: file, line: line) else { return }
        XCTAssertEqual(c.state, state, "\(id): \(c.cause)", file: file, line: line)
        XCTAssertEqual(c.fix, fix, "\(id): \(c.cause)", file: file, line: line)
    }

    func testActiveInstallPassesEveryCheckInOrder() {
        let checks = TelemetryDoctor.evaluate(facts())
        XCTAssertEqual(checks.map(\.id),
                       ["signature", "plist", "registration", "login-items", "launchd", "full-disk-access", "spool", "legacy"])
        XCTAssertEqual(checks.filter { $0.state != .pass }.map(\.id), [])
        XCTAssertTrue(check(checks, "launchd")?.cause.contains("pid 812") == true)
        XCTAssertTrue(check(checks, "launchd")?.cause.contains("last exit code (never exited)") == true)
    }

    func testNeverRegistered() {
        let checks = TelemetryDoctor.evaluate(facts {
            $0.serviceStatus = .notFound
            $0.launchd = .notFound
            $0.helperLogLastLine = nil
            $0.spoolMtime = nil
            $0.esService = ESServiceSnapshotModel(state: "not-loaded", spoolSize: 0, spoolMtime: "0001-01-01T00:00:00Z",
                                                  flooding: false, unparsedShare: 0)
        })
        assertCheck(checks, "plist", .pass, nil)
        assertCheck(checks, "registration", .fail, .register)
        assertCheck(checks, "login-items", .warn, nil)
        assertCheck(checks, "launchd", .warn, nil)
        assertCheck(checks, "full-disk-access", .warn, nil)
    }

    func testNeverRegisteredWithoutPlistOffersNoRegister() {
        let checks = TelemetryDoctor.evaluate(facts {
            $0.plistPresent = false
            $0.serviceStatus = .notFound
            $0.launchd = .notFound
        })
        assertCheck(checks, "plist", .fail, nil)
        assertCheck(checks, "registration", .fail, nil)
    }

    func testRequiresApproval() {
        let checks = TelemetryDoctor.evaluate(facts {
            $0.serviceStatus = .requiresApproval
            $0.launchd = .notFound
        })
        assertCheck(checks, "registration", .pass, nil)
        assertCheck(checks, "login-items", .fail, .openLoginItems)
        assertCheck(checks, "launchd", .warn, nil)
    }

    func testEnabledButNoLaunchdJob() {
        let checks = TelemetryDoctor.evaluate(facts { $0.launchd = .notFound })
        assertCheck(checks, "login-items", .pass, nil)
        assertCheck(checks, "launchd", .fail, .reregister)
        assertCheck(checks, "full-disk-access", .warn, nil)
    }

    func testRunningWithoutGrant() {
        let waiting = TelemetryDoctor.evaluate(facts {
            $0.helperLogLastLine = "2026/09/25 10:00:00 es-collector: eslogger exited: exit status 1 — waiting 1m0s for the eslogger permission grant"
            $0.spoolMtime = self.now.addingTimeInterval(-2 * 86400)
        })
        assertCheck(waiting, "full-disk-access", .fail, .openFullDiskAccess)

        let silent = TelemetryDoctor.evaluate(facts { $0.spoolMtime = self.now.addingTimeInterval(-91) })
        assertCheck(silent, "full-disk-access", .fail, .openFullDiskAccess)

        let noSpool = TelemetryDoctor.evaluate(facts { $0.spoolMtime = nil })
        assertCheck(noSpool, "full-disk-access", .fail, .openFullDiskAccess)

        let fresh = TelemetryDoctor.evaluate(facts { $0.spoolMtime = self.now.addingTimeInterval(-89) })
        assertCheck(fresh, "full-disk-access", .pass, nil)
    }

    func testAdhocSigned() {
        let checks = TelemetryDoctor.evaluate(facts {
            $0.appSignature = CodeSignature.parse(Self.codesignAdhocApp)
        })
        assertCheck(checks, "signature", .warn, nil)
        XCTAssertEqual(check(checks, "signature")?.cause, TelemetryDoctor.adhocCause)
        XCTAssertTrue(TelemetryDoctor.adhocCause.contains("make install"))
    }

    func testHelperWithWrongIdentifierFails() {
        let checks = TelemetryDoctor.evaluate(facts {
            $0.helperSignature = CodeSignature(identifier: "secure-agent-esd-55554944a1b2", adhoc: true, teamIdentifier: nil)
        })
        assertCheck(checks, "signature", .fail, nil)
    }

    func testUnreadableSignatureWarns() {
        let checks = TelemetryDoctor.evaluate(facts { $0.helperSignature = CodeSignature.parse(Self.codesignUnsigned) })
        assertCheck(checks, "signature", .warn, nil)
    }

    func testLegacyPresent() {
        let checks = TelemetryDoctor.evaluate(facts { $0.legacyInstalled = true })
        assertCheck(checks, "legacy", .fail, .removeLegacy)
    }

    func testCorruptStaleSpool() {
        let corrupt = TelemetryDoctor.evaluate(facts {
            $0.esService = ESServiceSnapshotModel(state: "not-loaded", spoolSize: 11_534_336,
                                                  spoolMtime: self.iso(self.now.addingTimeInterval(-2 * 86400)),
                                                  flooding: true, unparsedShare: 0.9998)
        })
        assertCheck(corrupt, "spool", .warn, .setAsideSpool)
        XCTAssertTrue(check(corrupt, "spool")?.cause.hasPrefix("100% of the spool does not parse") == true)

        let stillWriting = TelemetryDoctor.evaluate(facts {
            $0.esService = ESServiceSnapshotModel(state: "running", spoolSize: 11_534_336,
                                                  spoolMtime: self.iso(self.now.addingTimeInterval(-60)),
                                                  flooding: true, unparsedShare: 0.9)
        })
        assertCheck(stillWriting, "spool", .pass, nil)

        let noDaemon = TelemetryDoctor.evaluate(facts { $0.esService = nil })
        assertCheck(noDaemon, "spool", .warn, nil)
    }

    func testDaemonChecksListOnlyNonPassWithDetail() {
        let checks = TelemetryDoctor.evaluate(facts {
            $0.daemonChecks = [
                DaemonDoctorCheckModel(id: "hooks", title: "Hooks", state: "pass", detail: "3 of 3"),
                DaemonDoctorCheckModel(id: "file_telemetry", title: "File telemetry", state: "fail",
                                       detail: "collector not loaded", fix: "enable it in Settings"),
                DaemonDoctorCheckModel(id: "pairing", title: "Pairing", state: "skip", detail: ""),
            ]
        })
        XCTAssertNil(checks.first { $0.id == "daemon.hooks" })
        assertCheck(checks, "daemon.file_telemetry", .fail, nil)
        XCTAssertEqual(check(checks, "daemon.file_telemetry")?.cause, "collector not loaded")
        assertCheck(checks, "daemon.pairing", .warn, nil)
        XCTAssertEqual(check(checks, "daemon.pairing")?.cause, "skip")

        let silent = TelemetryDoctor.evaluate(facts { $0.daemonChecks = nil })
        assertCheck(silent, "daemon", .fail, nil)
    }

    func testOnlyPaneFixesWaitForTheUser() {
        XCTAssertEqual(DoctorFix.allCases.filter(\.needsUser), [.openLoginItems, .openFullDiskAccess])
    }

    // MARK: Set aside

    func testSetAsideRenamesSpoolAndRotatedSibling() throws {
        let dir = NSTemporaryDirectory() + "/es-spool-aside-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let spool = dir + "/es-spool.jsonl"
        try Data("{\"half".utf8).write(to: URL(fileURLWithPath: spool))
        try Data("line".utf8).write(to: URL(fileURLWithPath: spool + ".1"))

        let moved = try TelemetryDoctor.setAsideSpool(spoolPath: spool, now: now)

        let stamp = Int(now.timeIntervalSince1970)
        XCTAssertEqual(moved, ["\(spool).corrupt-\(stamp)", "\(spool).1.corrupt-\(stamp)"])
        XCTAssertFalse(FileManager.default.fileExists(atPath: spool))
        XCTAssertFalse(FileManager.default.fileExists(atPath: spool + ".1"))
        XCTAssertEqual(try String(contentsOfFile: "\(spool).corrupt-\(stamp)", encoding: .utf8), "{\"half")
        XCTAssertEqual(try String(contentsOfFile: "\(spool).1.corrupt-\(stamp)", encoding: .utf8), "line")
    }

    func testSetAsideWithOnlyTheSpool() throws {
        let dir = NSTemporaryDirectory() + "/es-spool-aside-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let spool = dir + "/es-spool.jsonl"
        try Data("x".utf8).write(to: URL(fileURLWithPath: spool))
        XCTAssertEqual(try TelemetryDoctor.setAsideSpool(spoolPath: spool, now: now).count, 1)
    }

    func testLastLineReadsTheLogTail() throws {
        let dir = NSTemporaryDirectory() + "/esd-log-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let log = dir + "/secure-agent-esd.log"
        let body = String(repeating: "filler line\n", count: 1000) + "last — waiting 1m0s for the eslogger permission grant\n\n"
        try Data(body.utf8).write(to: URL(fileURLWithPath: log))
        let last = TelemetryDoctor.lastLine(ofFileAt: log)
        XCTAssertEqual(last, "last — waiting 1m0s for the eslogger permission grant")
        XCTAssertTrue(TelemetryDoctor.logWaitsForGrant(last))
        XCTAssertNil(TelemetryDoctor.lastLine(ofFileAt: dir + "/missing.log"))
    }
}

import Darwin
import Foundation
import XCTest
@testable import SecureAgentMenubar

private final class SteppingUptime: @unchecked Sendable {
    private let lock = NSLock()
    private var next: TimeInterval = 0

    func read() -> TimeInterval {
        lock.lock()
        defer { lock.unlock() }
        let value = next
        next += 0.3
        return value
    }
}

@MainActor
final class DaemonSupervisorTests: XCTestCase {
    private func fixture(_ body: String, prefix: String = "") throws -> (dir: URL, script: String, starts: URL) {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let script = dir.appendingPathComponent("worker.sh")
        let starts = dir.appendingPathComponent("starts")
        let quoted = starts.path.replacingOccurrences(of: "'", with: "'\"'\"'")
        try ("#!/bin/sh\n" + prefix + "\nprintf '%s\\n' \"$$\" >> '\(quoted)'\n" + body + "\n")
            .write(to: script, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: script.path)
        return (dir, script.path, starts)
    }

    private func starts(_ url: URL) -> [String] {
        ((try? String(contentsOf: url, encoding: .utf8)) ?? "")
            .split(separator: "\n").map(String.init)
    }

    private func waitUntil(_ condition: () -> Bool, timeout: TimeInterval = 2) async -> Bool {
        let deadline = ProcessInfo.processInfo.systemUptime + timeout
        while !condition() && ProcessInfo.processInfo.systemUptime < deadline {
            try? await Task.sleep(for: .milliseconds(5))
        }
        return condition()
    }

    private func blockActor(for seconds: TimeInterval) {
        Thread.sleep(forTimeInterval: seconds)
    }

    func testDelayedExitCallbackDoesNotRenewFailureBudget() async throws {
        let f = try fixture("/bin/sleep 0.2\nexit 1")
        let supervisor = DaemonSupervisor(pathProvider: { f.script }, logDir: f.dir.path,
                                          maxRestarts: 1, stableRunDuration: 0.5,
                                          retryDelay: 0.01, maxRetryDelay: 0.01)
        defer { supervisor.stop(); try? FileManager.default.removeItem(at: f.dir) }
        supervisor.start()
        let retried = await waitUntil({ self.starts(f.starts).count == 2 })
        XCTAssertTrue(retried)
        blockActor(for: 0.8)
        let abandoned = await waitUntil({ supervisor.gaveUpRestarting }, timeout: 0.15)
        XCTAssertTrue(abandoned, "time spent waiting on the main actor is not child uptime")
        XCTAssertEqual(starts(f.starts).count, 2)
    }

    func testCancelledReadyRetryDoesNotReplaceNewRetry() async throws {
        let f = try fixture("exit 1")
        var attempts = 0
        let supervisor = DaemonSupervisor(pathProvider: { attempts += 1; return f.script + ".missing" },
                                          logDir: f.dir.path, retryDelay: 0.2, maxRetryDelay: 0.2)
        defer { supervisor.stop(); try? FileManager.default.removeItem(at: f.dir) }
        supervisor.start()
        await Task.yield() // let the first retry enter its sleep
        blockActor(for: 0.3) // its wake-up is now queued behind this actor
        supervisor.restart()
        let earlyRetry = await waitUntil({ attempts > 2 }, timeout: 0.1)
        XCTAssertFalse(earlyRetry, "the cancelled continuation must not launch ahead of the new delay")
    }

    func testRepeatedFailuresAcrossWindowStillExhaustBudget() async throws {
        let f = try fixture("exit 1")
        // Successive clock reads are 0.3 seconds apart. The full sequence
        // crosses 0.5 seconds without any individual run becoming stable.
        let clock = SteppingUptime()
        let supervisor = DaemonSupervisor(pathProvider: { f.script }, logDir: f.dir.path,
                                          maxRestarts: 2, stableRunDuration: 0.5,
                                          retryDelay: 0.01, maxRetryDelay: 0.02, uptime: clock.read)
        defer { supervisor.stop(); try? FileManager.default.removeItem(at: f.dir) }
        supervisor.start()
        let abandoned = await waitUntil({ supervisor.gaveUpRestarting }, timeout: 3)
        XCTAssertTrue(abandoned, "short failing runs must not renew the retry budget")
        XCTAssertEqual(starts(f.starts).count, 3, "initial run plus two retries")
        XCTAssertFalse(supervisor.isRunning)
        supervisor.start()
        XCTAssertFalse(supervisor.isRunning, "automatic start must respect exhaustion")
    }

    func testMissingHelperInBundleIsNotADevelopmentRun() {
        let root = URL(fileURLWithPath: "/not-installed/Secure Agent.app")
        XCTAssertEqual(DaemonSupervisor.bundledDaemonPath(in: root),
                       root.appendingPathComponent("Contents/Helpers/secure-agentd").path)
        XCTAssertNil(DaemonSupervisor.bundledDaemonPath(in: URL(fileURLWithPath: "/not-installed/dev")))
    }

    func testSpawnFailuresUseDeferredBoundedRetry() async throws {
        let f = try fixture("exit 0")
        let supervisor = DaemonSupervisor(pathProvider: { f.script + ".missing" }, logDir: f.dir.path,
                                          maxRestarts: 2, retryDelay: 0.02, maxRetryDelay: 0.04)
        defer { supervisor.stop(); try? FileManager.default.removeItem(at: f.dir) }
        supervisor.start()
        XCTAssertFalse(supervisor.gaveUpRestarting, "spawn failure must not recursively exhaust retries")
        let abandoned = await waitUntil({ supervisor.gaveUpRestarting })
        XCTAssertTrue(abandoned)
        XCTAssertFalse(supervisor.isRunning)
    }

    func testRestartReplacesRunningChild() async throws {
        let f = try fixture("exec /bin/sleep 60")
        let supervisor = DaemonSupervisor(pathProvider: { f.script }, logDir: f.dir.path)
        defer { supervisor.stop(); try? FileManager.default.removeItem(at: f.dir) }
        supervisor.start()
        let started = await waitUntil({ self.starts(f.starts).count == 1 })
        XCTAssertTrue(started)
        let first = starts(f.starts).first
        supervisor.restart()
        let restarted = await waitUntil({ self.starts(f.starts).count == 2 })
        XCTAssertTrue(restarted, "Restart must replace a running child")
        XCTAssertNotEqual(starts(f.starts).last, first)
        if let first, let pid = Int32(first) {
            XCTAssertEqual(kill(pid, 0), -1, "old child must exit before replacement")
            XCTAssertEqual(errno, ESRCH)
        }
    }

    func testStopCancelsPendingRetry() async throws {
        let f = try fixture("exit 1")
        let supervisor = DaemonSupervisor(pathProvider: { f.script }, logDir: f.dir.path,
                                          retryDelay: 0.2, maxRetryDelay: 0.2)
        defer { supervisor.stop(); try? FileManager.default.removeItem(at: f.dir) }
        supervisor.start()
        let exited = await waitUntil({ !supervisor.isRunning && self.starts(f.starts).count == 1 })
        XCTAssertTrue(exited)
        supervisor.stop()
        try await Task.sleep(for: .milliseconds(300))
        XCTAssertEqual(starts(f.starts).count, 1)
        XCTAssertFalse(supervisor.isRunning)
    }

    func testObsoleteExitCannotStartAnUnownedChild() throws {
        let f = try fixture("exec /bin/sleep 60")
        let supervisor = DaemonSupervisor(pathProvider: { f.script }, logDir: f.dir.path)
        defer { supervisor.stop(); try? FileManager.default.removeItem(at: f.dir) }
        let obsolete = Process()
        obsolete.executableURL = URL(fileURLWithPath: "/usr/bin/true")
        try obsolete.run()
        obsolete.waitUntilExit()
        supervisor.handleExit(obsolete)
        XCTAssertFalse(supervisor.isRunning, "a queued exit must belong to the current child")
    }

    func testRestartForcesOnlyTheChildIgnoringTermination() async throws {
        let f = try fixture("exec /bin/sleep 60", prefix: "trap '' TERM")
        let supervisor = DaemonSupervisor(pathProvider: { f.script }, logDir: f.dir.path,
                                          terminationTimeout: 0.05)
        defer { supervisor.stop(); try? FileManager.default.removeItem(at: f.dir) }
        supervisor.start()
        let started = await waitUntil({ self.starts(f.starts).count == 1 })
        XCTAssertTrue(started)
        let first = starts(f.starts).first
        supervisor.restart()
        let replaced = await waitUntil({ self.starts(f.starts).count == 2 })
        XCTAssertTrue(replaced, "an unresponsive child must not prevent restart forever")
        if let first, let pid = Int32(first) {
            XCTAssertEqual(kill(pid, 0), -1)
            XCTAssertEqual(errno, ESRCH)
        }
        supervisor.stop()
        let stopped = await waitUntil({ !supervisor.isRunning })
        XCTAssertTrue(stopped, "stop must also finish for a child ignoring SIGTERM")
        XCTAssertEqual(starts(f.starts).count, 2, "stop must not trigger another launch")
    }

    func testExplicitRestartRecoversAfterRetryExhaustion() async throws {
        let f = try fixture("exit 1")
        let supervisor = DaemonSupervisor(pathProvider: { f.script }, logDir: f.dir.path,
                                          maxRestarts: 0)
        defer { supervisor.stop(); try? FileManager.default.removeItem(at: f.dir) }
        supervisor.start()
        let abandoned = await waitUntil({ supervisor.gaveUpRestarting })
        XCTAssertTrue(abandoned)
        try "#!/bin/sh\nexec /bin/sleep 60\n".write(toFile: f.script, atomically: false, encoding: .utf8)
        supervisor.restart()
        XCTAssertTrue(supervisor.isRunning)
        XCTAssertFalse(supervisor.gaveUpRestarting)
    }

    func testLoggingFailureDoesNotPreventChildStartup() async throws {
        let f = try fixture("exec /bin/sleep 60")
        let logDir = f.dir.appendingPathComponent("not-a-directory")
        try Data().write(to: logDir)
        let supervisor = DaemonSupervisor(pathProvider: { f.script }, logDir: logDir.path)
        defer { supervisor.stop(); try? FileManager.default.removeItem(at: f.dir) }
        supervisor.start()
        let running = await waitUntil({ self.starts(f.starts).count == 1 })
        XCTAssertTrue(running)
        XCTAssertTrue(supervisor.isRunning)
    }

    func testNonRegularLogDoesNotBlockOrCrashStartup() async throws {
        let f = try fixture("printf output\nprintf diagnostic >&2\nexec /bin/sleep 60")
        let fifo = f.dir.appendingPathComponent("daemon.log").path
        XCTAssertEqual(mkfifo(fifo, S_IRUSR | S_IWUSR), 0)
        let supervisor = DaemonSupervisor(pathProvider: { f.script }, logDir: f.dir.path)
        defer { supervisor.stop(); try? FileManager.default.removeItem(at: f.dir) }
        supervisor.start()
        let running = await waitUntil({ self.starts(f.starts).count == 1 })
        XCTAssertTrue(running)
        XCTAssertTrue(supervisor.isRunning)
        let logged = await waitUntil({
            (try? String(contentsOf: f.dir.appendingPathComponent("daemon-err.log"), encoding: .utf8)) == "diagnostic"
        })
        XCTAssertTrue(logged, "closing parent log handles must preserve the child's descriptors")
    }
}

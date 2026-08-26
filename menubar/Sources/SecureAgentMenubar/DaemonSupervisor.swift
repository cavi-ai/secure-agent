import Darwin
import Foundation

/// Owns the lifetime of the bundled `secure-agentd` as a child process of the
/// menu bar app. The daemon runs only while the app runs:
///
///   - Quitting the app calls `stop()`, which terminates the child.
///   - If the app is killed abruptly (SIGKILL, crash), the daemon is reparented
///     to launchd and notices it has been orphaned, then exits on its own.
///
/// There is no LaunchAgent and no other mechanism by which the daemon can
/// outlive its visible owner. This is the whole point: the user sees the menu
/// bar icon and can quit it, and nothing keeps running behind their back.
@MainActor
public final class DaemonSupervisor {
    public static let shared = DaemonSupervisor()

    private var process: Process?
    private var stopping = false
    private var restartsInWindow = 0
    private var windowStart = Date()

    /// A daemon that cannot stay up must not become a spin loop, so restarts are
    /// rate limited; after the cap it is left down until the app is relaunched.
    private let maxRestarts = 5
    private let restartWindow: TimeInterval = 60

    private init() {}

    public var isRunning: Bool { process?.isRunning ?? false }

    /// Path to the daemon inside the app bundle; nil when running unbundled
    /// (e.g. `swift run` in development, where the daemon is run by hand).
    private var daemonPath: String? { SetupManager.shared.bundledDaemonPath }

    private var logDir: String { NSHomeDirectory() + "/Library/Logs/secure-agent" }

    /// Start the daemon if it is not already running. No-op (with a log line)
    /// when running unbundled, so development `swift run` sessions still work.
    public func start() {
        guard process == nil else { return }
        guard let path = daemonPath else {
            NSLog("[secure-agent] daemon helper not present in bundle; skipping start (unbundled/dev run)")
            return
        }
        stopping = false
        spawn(path)
    }

    private func spawn(_ path: String) {
        try? FileManager.default.createDirectory(atPath: logDir, withIntermediateDirectories: true)

        let p = Process()
        p.executableURL = URL(fileURLWithPath: path)
        if let out = appendingLog("daemon.log") { p.standardOutput = out }
        if let err = appendingLog("daemon-err.log") { p.standardError = err }
        p.terminationHandler = { proc in
            Task { @MainActor in DaemonSupervisor.shared.handleExit(proc) }
        }

        do {
            try p.run()
            process = p
            NSLog("[secure-agent] daemon started (pid \(p.processIdentifier))")
        } catch {
            process = nil
            NSLog("[secure-agent] failed to start daemon: \(error.localizedDescription)")
        }
    }

    private func handleExit(_ proc: Process) {
        // Ignore the exit of a process we already replaced.
        if let current = process, current !== proc { return }
        process = nil
        if stopping { return }

        let now = Date()
        if now.timeIntervalSince(windowStart) > restartWindow {
            windowStart = now
            restartsInWindow = 0
        }
        restartsInWindow += 1
        if restartsInWindow > maxRestarts {
            NSLog("[secure-agent] daemon exited \(restartsInWindow) times within \(Int(restartWindow))s; leaving it down until relaunch")
            return
        }
        NSLog("[secure-agent] daemon exited (status \(proc.terminationStatus)); restarting")
        if let path = daemonPath { spawn(path) }
    }

    /// Terminate the daemon and wait briefly for it to exit. Safe to call from
    /// `applicationWillTerminate`. SIGTERM first (the daemon shuts down cleanly
    /// on it), then SIGKILL as a backstop.
    public func stop() {
        stopping = true
        guard let p = process, p.isRunning else {
            process = nil
            return
        }
        p.terminationHandler = nil
        p.terminate() // SIGTERM

        let deadline = Date().addingTimeInterval(2.0)
        while p.isRunning && Date() < deadline {
            usleep(50_000)
        }
        if p.isRunning {
            kill(p.processIdentifier, SIGKILL)
        }
        process = nil
        NSLog("[secure-agent] daemon stopped")
    }

    private func appendingLog(_ name: String) -> FileHandle? {
        let path = "\(logDir)/\(name)"
        if !FileManager.default.fileExists(atPath: path) {
            FileManager.default.createFile(atPath: path, contents: nil)
        }
        guard let h = FileHandle(forWritingAtPath: path) else { return nil }
        h.seekToEndOfFile()
        return h
    }
}

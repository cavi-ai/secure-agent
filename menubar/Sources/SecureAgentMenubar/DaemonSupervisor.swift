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
/// outlive its visible owner. The app keeps a Dock control and Settings window
/// available even if macOS hides its menu bar status item.
@MainActor
public final class DaemonSupervisor: ObservableObject {
    public static let shared = DaemonSupervisor()

    private var process: Process?
    private var stopping = false
    private var consecutiveFailures = 0
    private var startedAt: TimeInterval?
    private var retryTask: Task<Void, Never>?
    private var terminationTask: Task<Void, Never>?
    private var restartRequested = false

    /// A daemon that cannot stay up must not become a spin loop, so restarts are
    /// bounded and delayed. Only a run lasting a full minute resets the budget.
    private let maxRestarts: Int
    private let stableRunDuration: TimeInterval

    private let pathProvider: () -> String?
    private let logDir: String
    private let retryDelay: TimeInterval
    private let maxRetryDelay: TimeInterval
    private let terminationTimeout: TimeInterval
    private let uptime: @Sendable () -> TimeInterval

    init(pathProvider: @escaping () -> String? = { bundledDaemonPath(in: Bundle.main.bundleURL) },
         logDir: String = NSHomeDirectory() + "/Library/Logs/secure-agent",
         maxRestarts: Int = 5, stableRunDuration: TimeInterval = 60,
         retryDelay: TimeInterval = 1, maxRetryDelay: TimeInterval = 16,
         terminationTimeout: TimeInterval = 10,
         uptime: @escaping @Sendable () -> TimeInterval = { ProcessInfo.processInfo.systemUptime }) {
        self.pathProvider = pathProvider
        self.logDir = logDir
        self.maxRestarts = maxRestarts
        self.stableRunDuration = stableRunDuration
        self.retryDelay = retryDelay
        self.maxRetryDelay = maxRetryDelay
        self.terminationTimeout = terminationTimeout
        self.uptime = uptime
    }

    public var isRunning: Bool { process?.isRunning ?? false }

    /// A broken .app bundle must take the visible spawn-failure path, rather
    /// than being mistaken for an intentionally unbundled development run.
    static func bundledDaemonPath(in bundleURL: URL) -> String? {
        let path = bundleURL.appendingPathComponent("Contents/Helpers/secure-agentd").path
        return bundleURL.pathExtension == "app" || FileManager.default.fileExists(atPath: path) ? path : nil
    }

    /// True when the restart rate limiter gave up: the daemon is down and will
    /// NOT come back on its own. The UI must surface this (with a Restart
    /// button) — otherwise the popover just says "Disconnected" forever.
    @Published public private(set) var gaveUpRestarting = false

    /// Reset the rate limiter and start the daemon again (user-initiated).
    public func restart() {
        retryTask?.cancel()
        retryTask = nil
        consecutiveFailures = 0
        gaveUpRestarting = false
        stopping = false
        if let p = process {
            restartRequested = true
            terminate(p)
        } else if let path = daemonPath {
            spawn(path)
        }
    }

    /// Path to the daemon inside the app bundle; nil when running unbundled
    /// (e.g. `swift run` in development, where the daemon is run by hand).
    private var daemonPath: String? { pathProvider() }


    /// Start the daemon if it is not already running. No-op (with a log line)
    /// when running unbundled, so development `swift run` sessions still work.
    public func start() {
        guard process == nil, retryTask == nil, !gaveUpRestarting else { return }
        guard let path = daemonPath else {
            NSLog("[secure-agent] daemon helper not present in bundle; skipping start (unbundled/dev run)")
            return
        }
        stopping = false
        spawn(path)
    }

    private func spawn(_ path: String) {
        guard !stopping, process == nil else { return }
        do {
            try FileManager.default.createDirectory(atPath: logDir, withIntermediateDirectories: true)
        } catch {
            NSLog("[secure-agent] daemon log directory unavailable: \(error.localizedDescription)")
        }

        let p = Process()
        p.executableURL = URL(fileURLWithPath: path)
        let out = appendingLog("daemon.log")
        let err = appendingLog("daemon-err.log")
        if let out { p.standardOutput = out }
        if let err { p.standardError = err }
        // Process duplicates these descriptors into the child. Release the
        // parent's handles on both successful and failed launches.
        defer {
            try? out?.close()
            try? err?.close()
        }
        let uptime = self.uptime
        p.terminationHandler = { [weak self] proc in
            let exitedAt = uptime()
            Task { @MainActor in self?.handleExit(proc, exitedAt: exitedAt) }
        }

        do {
            try p.run()
            process = p
            startedAt = uptime()
            NSLog("[secure-agent] daemon started (pid \(p.processIdentifier))")
        } catch {
            process = nil
            NSLog("[secure-agent] failed to start daemon: \(error.localizedDescription)")
            // A failed spawn has no terminationHandler, so without this the
            // daemon would stay down silently until relaunch.
            scheduleRetry()
        }
    }

    func handleExit(_ proc: Process, exitedAt: TimeInterval = ProcessInfo.processInfo.systemUptime) {
        // Queued callbacks from a released or replaced child are obsolete.
        guard let current = process, current === proc else { return }
        terminationTask?.cancel()
        terminationTask = nil
        let uptime = startedAt.map { exitedAt - $0 } ?? 0
        process = nil
        startedAt = nil
        if stopping { return }
        if restartRequested {
            restartRequested = false
            if let path = daemonPath { spawn(path) }
            return
        }
        if uptime >= stableRunDuration { consecutiveFailures = 0 }
        NSLog("[secure-agent] daemon exited (status \(proc.terminationStatus))")
        scheduleRetry()
    }

    /// Rate-limited retry shared by crash exits and spawn failures.
    private func scheduleRetry() {
        consecutiveFailures += 1
        if consecutiveFailures > maxRestarts {
            gaveUpRestarting = true
            NSLog("[secure-agent] daemon failed %d consecutive times; leaving it stopped until the user restarts it", consecutiveFailures)
            return
        }
        let delay = min(maxRetryDelay, retryDelay * pow(2, Double(consecutiveFailures - 1)))
        retryTask = Task { @MainActor [weak self] in
            do { try await Task.sleep(for: .seconds(delay)) }
            catch { return }
            guard !Task.isCancelled, let self, !self.stopping, !self.gaveUpRestarting,
                  self.process == nil else { return }
            self.retryTask = nil
            if let path = self.daemonPath { self.spawn(path) }
        }
    }

    /// Terminate the daemon. Safe to call from `applicationWillTerminate`.
    /// SIGTERM first, with a bounded asynchronous force-stop while the app is
    /// alive. Parent-exit detection in the daemon backs up the app quit path.
    public func stop() {
        stopping = true
        restartRequested = false
        retryTask?.cancel()
        retryTask = nil
        guard let p = process else { return }
        terminate(p)
        NSLog("[secure-agent] daemon stop requested")
    }

    /// Wait for this exact child to exit before replacing it. A child that
    /// ignores SIGTERM must not hold a user-requested restart open forever.
    private func terminate(_ p: Process) {
        guard p.isRunning else { return } // its queued exit callback owns cleanup
        p.terminate()
        guard terminationTask == nil else { return }
        terminationTask = Task { @MainActor [weak self] in
            do { try await Task.sleep(for: .seconds(self?.terminationTimeout ?? 10)) }
            catch { return }
            guard !Task.isCancelled, let self, let current = self.process, current === p, p.isRunning else { return }
            if kill(p.processIdentifier, SIGKILL) != 0 && errno != ESRCH {
                NSLog("[secure-agent] failed to stop daemon pid %d: %s", p.processIdentifier, strerror(errno))
            }
        }
    }

    /// Daemon logs append forever otherwise; truncate once they pass the cap
    /// (on spawn, not per write, so there is no per-line cost).
    private let maxLogBytes: UInt64 = 5 << 20 // 5 MiB

    private func appendingLog(_ name: String) -> FileHandle? {
        let path = "\(logDir)/\(name)"
        let fm = FileManager.default
        do {
            if !fm.fileExists(atPath: path), !fm.createFile(atPath: path, contents: nil) {
                throw CocoaError(.fileWriteUnknown)
            }
            let attributes = try fm.attributesOfItem(atPath: path)
            guard attributes[.type] as? FileAttributeType == .typeRegular else {
                throw CocoaError(.fileWriteInvalidFileName)
            }
            let h = try FileHandle(forWritingTo: URL(fileURLWithPath: path))
            do {
                if let size = attributes[.size] as? UInt64, size > maxLogBytes {
                    try h.truncate(atOffset: 0)
                }
                try h.seekToEnd()
                return h
            } catch {
                try? h.close()
                throw error
            }
        } catch {
            NSLog("[secure-agent] daemon log %@ unavailable: %@", name, error.localizedDescription)
            return nil
        }
    }
}

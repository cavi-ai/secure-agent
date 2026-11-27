import AppKit
import Darwin
import Foundation

/// One menu bar owner per user. Two app copies must not start competing daemons
/// against the same socket, database and console port.
final class InstanceLease {
    private var descriptor: Int32 = -1

    func acquire(at path: String) -> Bool {
        if descriptor >= 0 { return true }
        let fd = open(path, O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, S_IRUSR | S_IWUSR)
        guard fd >= 0 else { return false }
        var st = stat()
        guard fstat(fd, &st) == 0, (st.st_mode & S_IFMT) == S_IFREG, st.st_uid == getuid() else {
            close(fd)
            return false
        }
        guard flock(fd, LOCK_EX | LOCK_NB) == 0 else {
            close(fd)
            return false
        }
        descriptor = fd
        return true
    }

    func release() {
        guard descriptor >= 0 else { return }
        flock(descriptor, LOCK_UN)
        close(descriptor)
        descriptor = -1
    }

    deinit { release() }
}

@MainActor
final class AppInstanceGuard {
    static let shared = AppInstanceGuard()

    private let lease = InstanceLease()
    private init() {}

    private var lockPath: String {
        NSHomeDirectory() + "/.config/secure-agent/menubar.lock"
    }

    /// Older builds did not hold the lease, so also check Launch Services.
    private func otherCopies() -> [NSRunningApplication] {
        return NSRunningApplication.runningApplications(withBundleIdentifier: AppIdentity.bundleIdentifier)
            .filter { $0.processIdentifier != getpid() && !$0.isTerminated }
    }

    func claimOrExplain() async -> Bool {
        let dir = (lockPath as NSString).deletingLastPathComponent
        do {
            try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        } catch {
            explain("Secure Agent cannot create its local instance lock: \(error.localizedDescription)")
            return false
        }

        let existing = otherCopies()
        if existing.isEmpty {
            if lease.acquire(at: lockPath) { return true }
            // Hook liveness checks briefly probe the same lease. Allow that
            // transient reader to finish before reporting another app owner.
            for _ in 0..<5 {
                try? await Task.sleep(for: .milliseconds(10))
                guard !Task.isCancelled else { lease.release(); return false }
                if lease.acquire(at: lockPath) { return true }
            }
            explain("Secure Agent could not claim its local instance lock. Another copy may be starting, or the lock file may be inaccessible.")
            return false
        }

        let alert = NSAlert()
        alert.messageText = "Secure Agent is already running"
        alert.informativeText = "Two copies would compete for the same monitoring socket and console. Replace the running copy to use this build."
        alert.addButton(withTitle: "Replace running copy")
        alert.addButton(withTitle: "Keep running copy")
        NSApp.activate(ignoringOtherApps: true)
        let replace = alert.runModal() == .alertFirstButtonReturn
        guard replace else {
            return false
        }

        guard !Task.isCancelled else { return false }
        for app in existing { _ = app.terminate() }
        for _ in 0..<50 {
            if otherCopies().isEmpty && lease.acquire(at: lockPath) { return true }
            try? await Task.sleep(for: .milliseconds(100))
            if Task.isCancelled { lease.release(); return false }
        }
        lease.release()
        explain(otherCopies().isEmpty
                ? "The running copy quit, but Secure Agent could not claim its local instance lock. Check permissions on ~/.config/secure-agent/menubar.lock."
                : "The running copy did not quit. Quit it in Activity Monitor, then open this build again.")
        return false
    }

    func release() { lease.release() }

    private func explain(_ message: String) {
        let alert = NSAlert()
        alert.messageText = "Secure Agent could not start"
        alert.informativeText = message
        alert.addButton(withTitle: "OK")
        NSApp.activate(ignoringOtherApps: true)
        alert.runModal()
    }
}

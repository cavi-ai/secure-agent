import Foundation

/// Runs short helper binaries off the main actor: hdiutil, ditto, launchctl
/// and an administrator prompt can take seconds to minutes, and the menu bar
/// must not freeze through them.
enum ProcessRunner {
    typealias Result = (status: Int32, stdout: String, stderr: String)

    @discardableResult
    nonisolated static func run(_ bin: String, _ args: [String]) async -> Result {
        await Task.detached {
            let p = Process()
            p.executableURL = URL(fileURLWithPath: bin)
            p.arguments = args
            let out = Pipe(), err = Pipe()
            p.standardOutput = out
            p.standardError = err
            do {
                try p.run()
            } catch {
                return (-1, "", "\(error.localizedDescription)")
            }
            async let stdout = drainToEnd(out.fileHandleForReading)
            async let stderr = drainToEnd(err.fileHandleForReading)
            p.waitUntilExit() // bounded: pipes are drained concurrently
            return (p.terminationStatus, await stdout, await stderr)
        }.value
    }

    /// Drain a pipe fully on a side thread. Reading AFTER waitUntilExit()
    /// deadlocks once a pipe's 64KB buffer fills, so both pipes must be
    /// drained concurrently while the child runs.
    nonisolated private static func drainToEnd(_ handle: FileHandle) async -> String {
        await Task.detached {
            String(decoding: handle.readDataToEndOfFile(), as: UTF8.self)
        }.value
    }
}

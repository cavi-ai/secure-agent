import Darwin
import Foundation

/// Install a complete bundle without merging files into the running copy.
enum BundleUpdateInstaller {
    static func install(
        from source: URL, to destination: URL,
        verify: @escaping @Sendable (URL) async throws -> Void,
        prepareRelaunch: @escaping @Sendable () async throws -> Void
    ) async throws {
        try await Task.detached {
            let fm = FileManager.default
            for url in [source, destination] {
                let attributes = try fm.attributesOfItem(atPath: url.path)
                guard attributes[.type] as? FileAttributeType == .typeDirectory else {
                    throw CocoaError(.fileReadUnsupportedScheme)
                }
            }
            // A private sibling keeps the exchange on the installed volume.
            let staging = destination.deletingLastPathComponent()
                .appendingPathComponent(".secure-agent-update-\(UUID().uuidString)")
            try fm.createDirectory(at: staging, withIntermediateDirectories: false,
                                   attributes: [.posixPermissions: 0o700])
            var preserveBackup = false
            defer { if !preserveBackup { try? fm.removeItem(at: staging) } }
            let replacement = staging.appendingPathComponent(destination.lastPathComponent)
            try fm.copyItem(at: source, to: replacement)
            try await verify(replacement)
            try exchange(replacement, destination)
            do {
                try await prepareRelaunch()
            } catch {
                do {
                    try exchange(replacement, destination)
                } catch let rollbackError {
                    preserveBackup = true
                    throw InstallError.rollbackFailed(backup: replacement.path, cause: rollbackError.localizedDescription)
                }
                throw error
            }
        }.value
    }

    /// The child survives this app's exit; a main-queue timer cannot.
    static func startAfterExit(of pid: Int32, executable: URL, arguments: [String]) throws -> Process {
        guard pid > 0, FileManager.default.isExecutableFile(atPath: executable.path) else {
            throw CocoaError(.executableNotLoadable)
        }
        let helper = Process()
        helper.executableURL = URL(fileURLWithPath: "/bin/sh")
        helper.arguments = ["-c", """
            while kill -0 "$1" 2>/dev/null; do
                /bin/sleep 0.25
            done
            shift
            exec "$@"
            """, "secure-agent-relaunch", String(pid), executable.path] + arguments
        helper.standardInput = FileHandle.nullDevice
        helper.standardOutput = FileHandle.nullDevice
        helper.standardError = FileHandle.nullDevice
        try helper.run()
        return helper
    }

    private static func exchange(_ first: URL, _ second: URL) throws {
        guard renameatx_np(AT_FDCWD, first.path, AT_FDCWD, second.path, UInt32(RENAME_SWAP)) == 0 else {
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
        }
    }

    private enum InstallError: LocalizedError {
        case rollbackFailed(backup: String, cause: String)
        var errorDescription: String? {
            switch self {
            case let .rollbackFailed(backup, cause):
                return "Update rollback failed: \(cause). The previous app is preserved at \(backup)."
            }
        }
    }
}

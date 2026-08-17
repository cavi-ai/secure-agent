import Foundation
import AppKit

/// Orchestrates the full installation: builds binaries, stages them into an app bundle,
/// registers launch agents, and launches the menubar.
public final class Installer: NSObject {
    public enum Step: Int, CaseIterable {
        case welcome = 0
        case installing = 1
        case fullDiskAccess = 2
        case complete = 3
    }

    private let repoRoot: String
    private let bundleDest = "/Applications/secure-agent.app"

    @Published public var currentStep: Step = .welcome
    @Published public var progress: Double = 0.0   // 0…1 during .installing
    @Published public var statusMessage: String = ""
    @Published public var installError: Error? = nil

    private var observers: [((Step, Double, String, Error?) -> Void)] = []

    public override init() {
        var foundRoot = ""
        var dir = FileManager.default.currentDirectoryPath
        while !dir.isEmpty {
            let candidates = ["daemon", "menubar", "plugin"]
            if candidates.allSatisfy({ (dir as NSString).appendingPathComponent($0).isDirectory }) {
                foundRoot = dir
                break
            }
            let parent = (dir as NSString).deletingLastPathComponent
            if parent == dir { break }
            dir = parent
        }

        if foundRoot.isEmpty, let exe = ProcessInfo.processInfo.arguments.first {
            var p = (exe as NSString).deletingLastPathComponent
            while !p.isEmpty {
                if (p as NSString).appendingPathComponent("daemon").isDirectory {
                    foundRoot = p
                    break
                }
                let parent = (p as NSString).deletingLastPathComponent
                if parent == p { break }
                p = parent
            }
        }

        self.repoRoot = foundRoot.isEmpty ? NSHomeDirectory() : foundRoot
        super.init()
    }

    @objc public func runInstall() {
        do {
            try execute()
        } catch {
            self.installError = error
            notify(.complete, 1.0, "Installation failed: \(error.localizedDescription)", error)
        }
    }

    private func execute() throws {
        // 1. Build daemon
        step("Building secure-agentd…")
        try runCommand(["go", "build", "-o", bundleDest + "/Contents/MacOS/secure-agentd",
                        "./daemon/cmd/secure-agentd"], in: repoRoot)

        // 2. Build menubar and stage
        step("Building menubar…")
        let menubarBin = try buildMenubar()

        // 3. Create app bundle structure
        step("Staging app bundle…")
        try createAppBundle(menubarBin: menubarBin)

        // 4. Copy plugin hooks
        step("Installing plugin hooks…")
        try installPluginHooks()

        // 5. Register daemon LaunchAgent
        step("Registering daemon…")
        try registerDaemonLaunchAgent()

        // 6. Register menubar Login Item
        step("Registering menubar auto-start…")
        try registerMenubarLoginItem()

        // 7. Launch menubar
        step("Launching menubar…")
        launchMenubar()

        // 8. Check whether daemon is already running (if so, restart it)
        try startDaemonIfNeeded()

        step("Installation complete.")
        notify(.fullDiskAccess, 0.0, "Installed — check Full Disk Access below.", nil)
    }

    // ---- sub-steps -------------------------------------------------------

    private func createAppBundle(menubarBin: String) throws {
        let contents = bundleDest + "/Contents"
        let macosDir = contents + "/MacOS"
        let resourcesDir = contents + "/Resources"

        try FileManager.default.createDirectory(atPath: macosDir, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(atPath: resourcesDir, withIntermediateDirectories: true)

        // Move menubar binary into the bundle
        let destMenubar = macosDir + "/secure-agent-menubar"
        if FileManager.default.fileExists(atPath: menubarBin) {
            if FileManager.default.fileExists(atPath: destMenubar) {
                try FileManager.default.removeItem(atPath: destMenubar)
            }
            try FileManager.default.moveItem(atPath: menubarBin, toPath: destMenubar)
        }

        // Write Info.plist for the menubar app
        let plistPath = contents + "/Info.plist"
        let plist = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>CFBundleName</key><string>secure-agent</string>
            <key>CFBundleDisplayName</key><string>Secure Agent</string>
            <key>CFBundleIdentifier</key><string>com.cavi-ai.secure-agent</string>
            <key>CFBundleVersion</key><string>1.0.0</string>
            <key>CFBundleShortVersionString</key><string>1.0</string>
            <key>LSUIElement</key><true/>
            <key>LSBackgroundOnly</key><false/>
            <key>CFBundleExecutable</key><string>secure-agent-menubar</string>
        </dict>
        </plist>
        """
        try plist.write(toFile: plistPath, atomically: true, encoding: .utf8)
    }

    private func buildMenubar() throws -> String {
        let menubarDir = (repoRoot as NSString).appendingPathComponent("menubar")
        try runCommand(["swift", "build", "-c", "release"], in: menubarDir)
        // swiftc outputs to menubar/.build/release/secure-agent-menubar or arm64-apple-macosx/release/
        let releaseDir = menubarDir + "/.build/release"
        if FileManager.default.fileExists(atPath: releaseDir + "/secure-agent-menubar") {
            return releaseDir + "/secure-agent-menubar"
        }

        // Check arch-specific dir
        let archDir = menubarDir + "/.build/arm64-apple-macosx/release"
        if FileManager.default.fileExists(atPath: archDir + "/secure-agent-menubar") {
            return archDir + "/secure-agent-menubar"
        }

        throw InstallerError.cannotFindMenubarBinary
    }

    private func installPluginHooks() throws {
        let hookSrc = (repoRoot as NSString).appendingPathComponent("plugin/hooks")
        guard FileManager.default.fileExists(atPath: hookSrc) else { return }

        let targets = [
            NSHomeDirectory() + "/.claude/hooks",
            NSHomeDirectory() + "/.cursor/hooks",
            NSHomeDirectory() + "/.config/opencode/hooks",
        ]

        let hooks = try FileManager.default.contentsOfDirectory(atPath: hookSrc)
            .filter { $0.hasSuffix(".py") && !$0.hasPrefix("test_") }

        for target in targets {
            try FileManager.default.createDirectory(atPath: target, withIntermediateDirectories: true)
            for hook in hooks {
                let src = (hookSrc as NSString).appendingPathComponent(hook)
                let dst = (target as NSString).appendingPathComponent(hook)
                if FileManager.default.fileExists(atPath: dst) {
                    try FileManager.default.removeItem(atPath: dst)
                }
                try FileManager.default.createSymbolicLink(atPath: dst, withDestinationPath: src)
            }
        }
    }

    private func registerDaemonLaunchAgent() throws {
        let plistDest = NSHomeDirectory() + "/Library/LaunchAgents/com.cavi-ai.secure-agentd.plist"
        try FileManager.default.createDirectory(
            atPath: (plistDest as NSString).deletingLastPathComponent,
            withIntermediateDirectories: true)

        let daemonBin = bundleDest + "/Contents/MacOS/secure-agentd"
        let srcPlist = (repoRoot as NSString).appendingPathComponent("packaging/com.cavi-ai.secure-agentd.plist")

        if FileManager.default.fileExists(atPath: srcPlist) {
            let content = try String(contentsOfFile: srcPlist)
                .replacingOccurrences(of: "/usr/local/bin/secure-agentd", with: daemonBin)
                .replacingOccurrences(of: "/tmp/secure-agentd.log", with: NSHomeDirectory() + "/Library/Logs/secure-agent/daemon.log")
                .replacingOccurrences(of: "/tmp/secure-agentd.err.log", with: NSHomeDirectory() + "/Library/Logs/secure-agent/daemon-err.log")
            try content.write(toFile: plistDest, atomically: true, encoding: .utf8)
        } else {
            let plist = """
            <?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
            <plist version="1.0">
            <dict>
                <key>Label</key><string>com.cavi-ai.secure-agentd</string>
                <key>ProgramArguments</key>
                <array><string>\(daemonBin)</string></array>
                <key>RunAtLoad</key><true/>
                <key>KeepAlive</key><true/>
                <key>StandardOutPath</key><string>\(NSHomeDirectory())/Library/Logs/secure-agent/daemon.log</string>
                <key>StandardErrorPath</key><string>\(NSHomeDirectory())/Library/Logs/secure-agent/daemon-err.log</string>
            </dict>
            </plist>
            """
            try plist.write(toFile: plistDest, atomically: true, encoding: .utf8)
        }

        let uid = getuid()
        _ = runCommandSync(["launchctl", "bootout", "gui/\(uid)/com.cavi-ai.secure-agentd"])
        _ = runCommandSync(["launchctl", "bootstrap", "gui/\(uid)/com.cavi-ai.secure-agentd", plistDest])
        _ = runCommandSync(["launchctl", "unload", plistDest])
        _ = runCommandSync(["launchctl", "load", plistDest])
    }

    private func registerMenubarLoginItem() throws {
        let script = "tell application \"System Events\" to make login item at end with properties {path:\"\(bundleDest)\", hidden:false}"
        _ = runCommandSync(["osascript", "-e", script])
    }

    private func launchMenubar() {
        let url = URL(fileURLWithPath: bundleDest, isDirectory: true)
        NSWorkspace.shared.open(url)
    }

    private func startDaemonIfNeeded() throws {
        let existing = runCommandSync(["pgrep", "-x", "secure-agentd"])?.trimmingCharacters(in: .whitespacesAndNewlines)
        if let pid = existing, !pid.isEmpty {
            _ = runCommandSync(["kill", pid])
        }
        Thread.sleep(forTimeInterval: 1.0)
    }

    // ---- progress reporting -----------------------------------------------

    private func step(_ message: String) {
        self.statusMessage = message
        if currentStep == .installing {
            notify(currentStep, progress, message, nil)
        }
    }

    private func notify(_ step: Step, _ progress: Double, _ message: String, _ error: Error?) {
        currentStep = step
        self.progress = progress
        self.statusMessage = message
        if let error { self.installError = error }
    }

    func addObserver(_ closure: @escaping (Step, Double, String, Error?) -> Void) {
        observers.append(closure)
    }

    func notifyObservers() {
        for obs in observers {
            obs(currentStep, progress, statusMessage, installError)
        }
    }

    // ---- process helpers --------------------------------------------------

    private func runCommand(_ args: [String], in directory: String) throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        process.arguments = args
        process.currentDirectoryPath = directory

        let errorPipe = Pipe()
        process.standardError = errorPipe
        process.standardOutput = FileHandle.nullDevice

        try process.run()
        process.waitUntilExit()

        guard process.terminationStatus == 0 else {
            let errOutput = String(data: errorPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
            throw InstallerError.commandFailed(args.joined(separator: " "), errOutput.trimmingCharacters(in: .whitespacesAndNewlines))
        }
    }

    private func runCommandSync(_ args: [String]) -> String? {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        process.arguments = args

        let outputPipe = Pipe()
        process.standardOutput = outputPipe
        process.standardError = outputPipe

        try? process.run()
        process.waitUntilExit()

        let data = outputPipe.fileHandleForReading.readDataToEndOfFile()
        return String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    enum InstallerError: LocalizedError {
        case commandFailed(String, String)
        case cannotFindMenubarBinary

        var errorDescription: String? {
            switch self {
            case .commandFailed(let cmd, let output):
                return "Command failed: \(cmd)\n\(output)"
            case .cannotFindMenubarBinary:
                return "Could not locate the built menubar binary. Is Swift toolchain available?"
            }
        }
    }
}

extension String {
    var isDirectory: Bool {
        var isDir = ObjCBool(false)
        return FileManager.default.fileExists(atPath: self, isDirectory: &isDir) && isDir.boolValue
    }
}

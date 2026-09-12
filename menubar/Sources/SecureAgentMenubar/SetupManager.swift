import AppKit
import Foundation
import ServiceManagement

/// Owns first-run setup and teardown: harness hooks, login item, CLI symlink,
/// and Full Disk Access guidance. The daemon itself is not set up here — it is
/// a child process of the app (see `DaemonSupervisor`), not a LaunchAgent, so
/// it can never outlive the visible menu bar app.
@MainActor
public final class SetupManager: ObservableObject {
    public static let shared = SetupManager()

    public static let daemonLabel = "com.cavi-ai.secure-agentd"
    /// The privileged Endpoint Security collector (root LaunchDaemon).
    public static let esCollectorLabel = "com.cavi-ai.secure-agent-esd"
    /// The LaunchDaemon runs THE DAEMON BINARY ITSELF in --es-collector
    /// mode — the binary the operator already granted Full Disk Access.
    /// No separate helper, no separate FDA drag: one grant covers it.
    public static let esCollectorInstallPath = Bundle.main.bundleURL
        .appendingPathComponent("Contents/Helpers/secure-agentd").path

    @Published public private(set) var isDaemonRunning = false
    @Published public private(set) var areHooksInstalled = false
    /// Result of the onboarding hook self-test: nil = passed, string = the
    /// human-readable failure. Not part of needsSetup — it is a diagnostic.
    @Published public private(set) var hookSelfTestFailure: String?
    @Published public private(set) var hookSelfTestRunning = false
    @Published public private(set) var lastError: String?
    /// Local advisor: whether a model server answers on the loopback endpoint
    /// and whether the daemon config has the advisor enabled.
    @Published public private(set) var advisorServerReachable = false
    @Published public private(set) var advisorEnabled = false
    /// Last-persisted advisor config (mode/endpoint/model) — the Settings
    /// tab's restore source so the advisor persists across restarts.
    @Published public private(set) var advisorPersisted: (mode: String?, endpoint: String?, model: String?) = (nil, nil, nil)
    /// Provider names the operator disabled (from disabled_agents in
    /// config.yaml). Toggling writes the file; the daemon's config watcher
    /// picks it up on its next Load (agents must be statically configured —
    /// tagger rebuilds on restart, not hot).
    @Published public private(set) var disabledAgents: [String] = []

    /// All agent definitions shipped in the daemon's defaults (name → match
    /// strings), for the Providers tab. Kept in sync with
    /// daemon/internal/config/defaults.yaml manually.
    public static let knownAgents: [(name: String, matches: [String])] = [
        ("claude", ["claude"]),
        ("cursor", ["Cursor Helper", "cursor"]),
        ("codex", ["codex"]),
        ("opencode", ["opencode", "OpenCode Helper"]),
        ("antigravity", ["antigravity", "Antigravity Helper"]),
        ("windsurf", ["windsurf"]),
        ("aider", ["aider"]),
        ("gemini", ["gemini-cli", "gemini"]),
        ("codeium", ["codeium"]),
        ("copilot", ["copilot"]),
        ("ollama", ["ollama", "llama-server", "llama.cpp"]),
        ("lm-studio", ["lm studio", "lmstudio"]),
    ]

    /// Toggle one provider. Writes disabled_agents; the daemon applies it on
    /// its next config load (restart — agents are static per lifetime).
    public func setAgentDisabled(_ name: String, disabled: Bool) {
        do {
            var off = disabledAgents
            if disabled { if !off.contains(name) { off.append(name) } }
            else { off.removeAll { $0 == name } }
            let updated = Self.setDisabledAgents(configYAML(), disabled: off)
            let dir = (configPath as NSString).deletingLastPathComponent
            try fm.createDirectory(atPath: dir, withIntermediateDirectories: true)
            try updated.write(toFile: configPath, atomically: true, encoding: .utf8)
            disabledAgents = off
        } catch {
            report(error)
        }
    }
    /// Neutral guidance after an advisor toggle (the daemon reads config at
    /// start, so a change needs an app restart). Not an error.
    @Published public private(set) var advisorNote: String?
    /// Loopback model servers + the curated managed list, from the daemon's
    /// /advisor/discover. Drives the Advisor settings dropdowns.
    @Published public private(set) var advisorDiscovery = AdvisorDiscovery(servers: [], managedModels: [])

    /// The advisor's default loopback endpoint (the daemon enforces loopback;
    /// the menubar only ever probes this one).
    public nonisolated static let advisorEndpoint = "http://127.0.0.1:8080"

    private let fm = FileManager.default
    private let home = NSHomeDirectory()

    private var launchAgentsDir: String { "\(home)/Library/LaunchAgents" }
    /// Path of the legacy daemon LaunchAgent. Older versions installed a
    /// KeepAlive=true agent here that respawned the daemon behind the user's
    /// back; it is now migrated away on launch (see `migrateLegacyLaunchAgent`).
    private var daemonPlistPath: String { "\(launchAgentsDir)/\(Self.daemonLabel).plist" }

    /// Path to the daemon inside the app bundle. Nil when running unbundled
    /// (e.g. `swift run` during development).
    public var bundledDaemonPath: String? {
        let path = Bundle.main.bundleURL
            .appendingPathComponent("Contents/Helpers/secure-agentd").path
        return fm.fileExists(atPath: path) ? path : nil
    }

    public var bundledCLIPath: String? {
        let path = Bundle.main.bundleURL
            .appendingPathComponent("Contents/Helpers/secure-agent").path
        return fm.fileExists(atPath: path) ? path : nil
    }

    private var bundledHooksDir: String? {
        let path = Bundle.main.bundleURL
            .appendingPathComponent("Contents/Resources/hooks").path
        return fm.fileExists(atPath: path) ? path : nil
    }

    public var isBundled: Bool { bundledDaemonPath != nil }

    private init() {}

    // MARK: - State

    public func refreshState() async {
        let statusReachable = (try? await DaemonClient().fetchStatus().running) ?? false
        isDaemonRunning = DaemonSupervisor.shared.isRunning || statusReachable
        // ALL harnesses must carry the hook — `contains` used to announce
        // "Hooks installed" when only one of three targets had it, leaving the
        // other two unprotected while the wizard claimed otherwise.
        areHooksInstalled = Self.hookTargets.allSatisfy { target in
            fm.fileExists(atPath: "\(target)/secret_guard.py")
        }
        advisorEnabled = Self.advisorConfigIsEnabled(configYAML())
        advisorPersisted = Self.advisorConfig(configYAML())
        disabledAgents = Self.disabledAgents(configYAML())
        advisorServerReachable = await Self.probeAdvisorServer()
        advisorDiscovery = (try? await DaemonClient().fetchAdvisorDiscover())
            ?? AdvisorDiscovery(servers: [], managedModels: [])
    }

    /// The only mandatory setup step is installing the harness hooks; the daemon
    /// starts automatically with the app. FDA, login item, and the CLI are
    /// optional extras and do not force the wizard open.
    public var needsSetup: Bool {
        isBundled && !areHooksInstalled
    }

    // MARK: - Local advisor

    private var configPath: String { "\(home)/.config/secure-agent/config.yaml" }

    private func configYAML() -> String {
        (try? String(contentsOfFile: configPath, encoding: .utf8)) ?? ""
    }

    /// Probe the loopback model server (OpenAI-compatible /v1/models). Short
    /// timeout: this runs on every wizard open and must never hang it.
    public nonisolated static func probeAdvisorServer() async -> Bool {
        guard let url = URL(string: "\(advisorEndpoint)/v1/models") else { return false }
        var req = URLRequest(url: url)
        req.timeoutInterval = 1.5
        guard let (_, resp) = try? await URLSession.shared.data(for: req),
              let http = resp as? HTTPURLResponse else { return false }
        return (200..<300).contains(http.statusCode)
    }

    /// Flip advisor.enabled in config.yaml. Line-based and deliberately
    /// narrow: config.yaml is user-owned, so we rewrite only the enabled line
    /// inside the advisor block, or append the whole block when absent.
    /// Writes are atomic — a torn config would be a loud daemon error.
    public func setAdvisorEnabled(_ enabled: Bool) {
        do {
            let updated = Self.advisorConfigUpdating(configYAML(), enabled: enabled)
            let dir = (configPath as NSString).deletingLastPathComponent
            try fm.createDirectory(atPath: dir, withIntermediateDirectories: true)
            try updated.write(toFile: configPath, atomically: true, encoding: .utf8)
            advisorEnabled = enabled
            advisorNote = "Advisor " + (enabled ? "enabled" : "disabled") + " — applied live (daemon hot-reloads config)."
        } catch {
            report(error)
        }
    }

    public enum AdvisorMode: String, Sendable {
        case managed, existing
    }

    /// Write the full advisor block for one of the two first-class paths:
    /// managed (daemon spawns the model server; no endpoint in the file) or
    /// existing (loopback endpoint + model from the discovery dropdowns).
    /// Atomic write; the restart note tells the user the daemon needs a
    /// relaunch to pick it up.
    public func setAdvisorConfig(mode: AdvisorMode, endpoint: String?, model: String) {
        do {
            let updated = Self.advisorConfigSetting(configYAML(), mode: mode, endpoint: endpoint, model: model)
            let dir = (configPath as NSString).deletingLastPathComponent
            try fm.createDirectory(atPath: dir, withIntermediateDirectories: true)
            try updated.write(toFile: configPath, atomically: true, encoding: .utf8)
            advisorEnabled = true
            advisorNote = "Advisor configured (\(mode.rawValue)) — applied live (daemon hot-reloads config)."
        } catch {
            report(error)
        }
    }

    /// Replace the whole advisor block (or append one) with the given path
    /// config, preserving every other byte of the user's config.yaml. Pure
    /// and line-based like the other helpers: block = `advisor:` up to the
    /// next top-level key.
    public nonisolated static func advisorConfigSetting(_ yaml: String, mode: AdvisorMode, endpoint: String?, model: String) -> String {
        // Strip any existing advisor block.
        let lines = yaml.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
        var kept: [String] = []
        var inAdvisor = false
        for line in lines {
            if line.hasPrefix("advisor:") { inAdvisor = true; continue }
            if inAdvisor && !line.hasPrefix(" ") && !line.hasPrefix("#") && !line.trimmingCharacters(in: .whitespaces).isEmpty {
                inAdvisor = false
            }
            if !inAdvisor { kept.append(line) }
        }
        var base = kept.joined(separator: "\n")
        while base.hasSuffix("\n\n") { base.removeLast() }

        let block: String
        switch mode {
        case .managed:
            block = """

            # Local advisor (managed): the daemon spawns and supervises the model
            # server itself — no endpoint needed. Loopback-only, enforced in code.
            advisor:
              enabled: true
              managed: true
              managed_model: "\(model)"
              timeout_ms: 8000
            """
        case .existing:
            block = """

            # Local advisor (existing server): a locally served model triages flags
            # and writes incident narratives. Loopback-only, enforced in code.
            advisor:
              enabled: true
              endpoint: "\(endpoint ?? advisorEndpoint)"
              model: "\(model)"
              timeout_ms: 8000
            """
        }
        if !base.isEmpty && !base.hasSuffix("\n") { base += "\n" }
        return base + block + "\n"
    }

    /// True when the YAML has an advisor block with `enabled: true`.
    /// Line-based: a real YAML parser would be overkill for one boolean.
    /// Read the disabled_agents list (top-level key, "- name" lines).
    public nonisolated static func disabledAgents(_ yaml: String) -> [String] {
        var inList = false
        var out: [String] = []
        for line in yaml.split(separator: "\n", omittingEmptySubsequences: false) {
            let s = String(line)
            if s.hasPrefix("disabled_agents:") { inList = true; continue }
            if inList {
                let t = s.trimmingCharacters(in: .whitespaces)
                if t.hasPrefix("-") {
                    out.append(t.dropFirst().trimmingCharacters(in: .whitespaces)
                        .replacingOccurrences(of: "\"", with: ""))
                    continue
                }
                break // first non-dash line ends the list
            }
        }
        return out
    }

    /// Write the disabled_agents list (replace or append; preserves the rest
    /// of the file byte-for-byte).
    public nonisolated static func setDisabledAgents(_ yaml: String, disabled: [String]) -> String {
        var lines = yaml.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
        // Strip existing block.
        var kept: [String] = []
        var skipping = false
        for line in lines {
            if line.hasPrefix("disabled_agents:") { skipping = true; continue }
            if skipping {
                if line.hasPrefix("  -") || line.hasPrefix(" -") { continue }
                skipping = false
            }
            kept.append(line)
        }
        lines = kept
        if disabled.isEmpty { return lines.joined(separator: "\n") }
        var block = ["disabled_agents:"]
        block += disabled.map { "  - \($0)" }
        // Insert at the top (after any leading comments) — top-level keys
        // read fine anywhere, but top keeps it discoverable.
        var idx = 0
        while idx < lines.count && (lines[idx].hasPrefix("#") || lines[idx].trimmingCharacters(in: .whitespaces).isEmpty) {
            idx += 1
        }
        lines.insert(contentsOf: block, at: idx)
        return lines.joined(separator: "\n")
    }

    /// The persisted advisor config (mode, endpoint, model) — what the
    /// Settings tab restores on open so the advisor "sticks" instead of
    /// defaulting to managed-every-launch.
    public nonisolated static func advisorConfig(_ yaml: String) -> (mode: String?, endpoint: String?, model: String?) {
        var inAdvisor = false
        var mode: String?
        var endpoint: String?
        var model: String?
        var managed: Bool?
        for line in yaml.split(separator: "\n", omittingEmptySubsequences: false) {
            let s = String(line)
            if s.hasPrefix("advisor:") { inAdvisor = true; continue }
            if inAdvisor && !s.hasPrefix(" ") && !s.hasPrefix("#") && !s.trimmingCharacters(in: .whitespaces).isEmpty {
                inAdvisor = false
            }
            guard inAdvisor else { continue }
            let t = s.trimmingCharacters(in: .whitespaces)
            if t.hasPrefix("managed:") {
                managed = t.replacingOccurrences(of: "managed:", with: "")
                    .trimmingCharacters(in: .whitespaces)
                    .split(separator: "#").first.map { $0.trimmingCharacters(in: .whitespaces) == "true" }
            } else if t.hasPrefix("managed_model:") {
                model = t.replacingOccurrences(of: "managed_model:", with: "")
                    .trimmingCharacters(in: .whitespaces)
                    .replacingOccurrences(of: "\"", with: "")
            } else if t.hasPrefix("endpoint:") {
                endpoint = t.replacingOccurrences(of: "endpoint:", with: "")
                    .trimmingCharacters(in: .whitespaces)
                    .replacingOccurrences(of: "\"", with: "")
            } else if t.hasPrefix("model:") {
                model = t.replacingOccurrences(of: "model:", with: "")
                    .trimmingCharacters(in: .whitespaces)
                    .replacingOccurrences(of: "\"", with: "")
            }
        }
        let m = managed.map { $0 ? "managed" : "existing" }
        return (m, endpoint, model)
    }

    public nonisolated static func advisorConfigIsEnabled(_ yaml: String) -> Bool {
        var inAdvisor = false
        for line in yaml.split(separator: "\n", omittingEmptySubsequences: false) {
            let s = String(line)
            if s.hasPrefix("advisor:") { inAdvisor = true; continue }
            // Any non-indented, non-comment line ends the advisor block.
            if inAdvisor && !s.hasPrefix(" ") && !s.hasPrefix("#") && !s.trimmingCharacters(in: .whitespaces).isEmpty {
                inAdvisor = false
            }
            if inAdvisor {
                let t = s.trimmingCharacters(in: .whitespaces)
                if t.hasPrefix("enabled:") {
                    return t.replacingOccurrences(of: "enabled:", with: "")
                        .trimmingCharacters(in: .whitespaces)
                        .split(separator: "#").first.map { $0.trimmingCharacters(in: .whitespaces) == "true" } ?? false
                }
            }
        }
        return false
    }

    /// Return the YAML with advisor.enabled set. Appends the full block when
    /// the advisor key is absent; preserves all other content byte-for-byte.
    public nonisolated static func advisorConfigUpdating(_ yaml: String, enabled: Bool) -> String {
        let value = enabled ? "true" : "false"
        var lines = yaml.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
        var inAdvisor = false
        var blockStart = -1
        var blockEnd = lines.count
        for (i, s) in lines.enumerated() {
            if s.hasPrefix("advisor:") { inAdvisor = true; blockStart = i; continue }
            if inAdvisor && !s.hasPrefix(" ") && !s.hasPrefix("#") && !s.trimmingCharacters(in: .whitespaces).isEmpty {
                blockEnd = i
                break
            }
        }
        if blockStart >= 0 {
            for i in blockStart..<blockEnd {
                let t = lines[i].trimmingCharacters(in: .whitespaces)
                if t.hasPrefix("enabled:") {
                    let indent = lines[i].hasPrefix(" ") ? String(lines[i].prefix(while: { $0 == " " })) : ""
                    lines[i] = "\(indent)enabled: \(value)"
                    return lines.joined(separator: "\n")
                }
            }
            // Block exists but no enabled key: insert right after `advisor:`.
            lines.insert("  enabled: \(value)", at: blockStart + 1)
            return lines.joined(separator: "\n")
        }
        var block = """

        # Local triage advisor (opt-in): a locally served model triages flags and
        # writes incident narratives. Loopback-only, enforced in code.
        # See docs/ADVISOR_THREAT_MODEL.md.
        advisor:
          enabled: \(value)
          endpoint: "\(advisorEndpoint)"
          model: ""
          timeout_ms: 8000
        """
        if !yaml.isEmpty && !yaml.hasSuffix("\n") { block = "\n" + block }
        return yaml + block + "\n"
    }

    // MARK: - Legacy LaunchAgent migration

    /// Remove the KeepAlive daemon LaunchAgent left by older versions. Those
    /// versions ran the daemon under launchd, so it respawned when killed and
    /// kept running after the menu bar app was quit. Now the app owns the
    /// daemon's lifetime directly, so any leftover agent must be torn down.
    public func migrateLegacyLaunchAgent() {
        guard fm.fileExists(atPath: daemonPlistPath) else { return }
        let uid = getuid()
        Self.run(["/bin/launchctl", "bootout", "gui/\(uid)/\(Self.daemonLabel)"])
        try? fm.removeItem(atPath: daemonPlistPath)
        NSLog("[secure-agent] removed legacy daemon LaunchAgent")
    }

    // MARK: - Harness hooks

    public static let hookTargets: [String] = [
        NSHomeDirectory() + "/.claude/hooks",
        NSHomeDirectory() + "/.cursor/hooks",
        NSHomeDirectory() + "/.config/opencode/hooks",
    ]

    public func installHooks() throws {
        guard let srcDir = bundledHooksDir else { throw SetupError.notBundled }
        lastError = nil
        let hooks = try fm.contentsOfDirectory(atPath: srcDir)
            .filter { $0.hasSuffix(".py") && !$0.hasPrefix("test_") }
        for target in Self.hookTargets {
            try fm.createDirectory(atPath: target, withIntermediateDirectories: true)
            for hook in hooks {
                let dst = "\(target)/\(hook)"
                if fm.fileExists(atPath: dst) { try fm.removeItem(atPath: dst) }
                try fm.copyItem(atPath: "\(srcDir)/\(hook)", toPath: dst)
            }
        }
    }

    /// Run the self-test and publish the outcome to the wizard UI.
    public func runHookSelfTest() async {
        hookSelfTestRunning = true
        defer { hookSelfTestRunning = false }
        hookSelfTestFailure = await selfTestHooks()
    }

    /// Fire a synthetic guarded tool call through the installed hook and check
    /// it answers. A green check here means: python3 present, hook executable,
    /// protocol intact — the whole chain a silent failure would otherwise hide.
    /// Returns nil on success, or a human-readable reason on failure.
    public func selfTestHooks() async -> String? {
        // Prefer the Claude install; any target with the hook works.
        let hookPath = Self.hookTargets
            .map { "\($0)/secret_guard.py" }
            .first { fm.fileExists(atPath: $0) }
        guard let hook = hookPath else {
            return "secret_guard.py is not installed"
        }
        let payload = #"{"hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{"file_path":"/tmp/secure-agent-self-test-allow.txt"}}"#
        guard let stdinData = payload.data(using: .utf8) else { return "internal: payload encoding" }

        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        p.arguments = ["python3", hook]
        let inPipe = Pipe(), outPipe = Pipe(), errPipe = Pipe()
        p.standardInput = inPipe
        p.standardOutput = outPipe
        p.standardError = errPipe
        do {
            try p.run()
            inPipe.fileHandleForWriting.write(stdinData)
            inPipe.fileHandleForWriting.closeFile()
        } catch {
            return "could not launch python3: \(error.localizedDescription)"
        }

        // Hooks answer in well under a second; don't hang the wizard. Read
        // stdout/stderr CONCURRENTLY with the wait — a hook that writes more
        // than the 64KB pipe buffer before exiting would otherwise deadlock
        // against the busy-wait and false-fail as a timeout.
        async let outData = outPipe.fileHandleForReading.readDataToEndOfFile()
        async let errData = errPipe.fileHandleForReading.readDataToEndOfFile()
        let deadline = Date().addingTimeInterval(10)
        while p.isRunning && Date() < deadline {
            try? await Task.sleep(nanoseconds: 100_000_000)
        }
        if p.isRunning {
            p.terminate()
            return "hook timed out after 10s"
        }
        _ = await errData
        let out = String(data: await outData, encoding: .utf8) ?? ""
        guard let json = try? JSONSerialization.jsonObject(with: Data(out.utf8)) as? [String: Any] else {
            return "hook produced no JSON (python3 missing or hook crashed)"
        }
        if json["permission"] as? String == "allow" {
            return nil
        }
        return "hook answered \(json["permission"] ?? "nothing") for a harmless read — expected allow"
    }

    // MARK: - Login item

    public func enableLoginItem() throws {
        lastError = nil
        if SMAppService.mainApp.status != .enabled {
            try SMAppService.mainApp.register()
        }
    }

    /// The toggle must go both ways — a one-way "Open at Login" is a trap.
    public func disableLoginItem() throws {
        lastError = nil
        if SMAppService.mainApp.status == .enabled {
            try SMAppService.mainApp.unregister()
        }
    }

    public var isLoginItemEnabled: Bool {
        SMAppService.mainApp.status == .enabled
    }

    // MARK: - Privileged ES collector

    /// Whether the LaunchDaemon plist exists (the helper is installed,
    /// regardless of whether TCC has granted eslogger yet).
    public var esCollectorDaemonInstalled: Bool {
        FileManager.default.fileExists(atPath: "/Library/LaunchDaemons/\(Self.esCollectorLabel).plist")
    }

    /// Whether file telemetry is actually live: the privileged helper is
    /// running AND writing the spool (proof eslogger got its ES client —
    /// i.e. the user has flipped the eslogger switch in Settings).
    public var isESCollectorInstalled: Bool {
        guard let attrs = try? FileManager.default.attributesOfItem(atPath: "/var/db/secure-agent/es-spool.jsonl"),
              let size = attrs[.size] as? UInt64, size > 0 else { return false }
        return true
    }

    /// Installs the privileged ES collector: writes the LaunchDaemon plist
    /// (running THE DAEMON binary in --es-collector mode — the binary the
    /// operator already FDA-granted) and bootstraps it. One osascript admin
    /// prompt; no helper to stage, no second FDA drag.
    public func installESCollector() throws {
        lastError = nil
        guard bundledDaemonPath != nil else { throw SetupError.notBundled }
        let plist = Self.esPlistB64
        let label = Self.esCollectorLabel
        let shell = "echo '\(plist)' | base64 -d > /Library/LaunchDaemons/\(label).plist" +
            " && chown root:wheel /Library/LaunchDaemons/\(label).plist && chmod 644 /Library/LaunchDaemons/\(label).plist" +
            " && launchctl bootstrap system /Library/LaunchDaemons/\(label).plist"
        let script = "do shell script \(shellAppleScriptLiteral(shell)) with administrator privileges"
        guard runAppleScriptAdmin(script) else {
            if lastError == nil { lastError = "the privileged collector install was cancelled" }
            throw SetupError.notBundled
        }
        Task { await refreshState() }
    }

    /// Escapes a shell command into an AppleScript string literal.
    private func shellAppleScriptLiteral(_ s: String) -> String {
        "\"\(s.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\""))\""
    }

    /// Async wrapper for the guided card (throws so the caller can poll on
    /// success only).
    public func installESCollectorAsync() async throws {
        try installESCollector()
    }

    /// Deep-link System Settings → Full Disk Access (the pane where the
    /// eslogger switch lives after the helper's first failed run).
    public func openESPermissions() {
        if let url = URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles") {
            NSWorkspace.shared.open(url)
        }
    }

    /// Removes the LaunchDaemon + binary. Also called by uninstallAll.
    public func uninstallESCollector() {
        let script = "do shell script \"launchctl bootout system /Library/LaunchDaemons/\(Self.esCollectorLabel).plist 2>/dev/null; rm -f /Library/LaunchDaemons/\(Self.esCollectorLabel).plist; true\" with administrator privileges"
        _ = Self.run(["/usr/bin/osascript", "-e", script])
    }

    /// LaunchDaemon definition: keep-alive, root, one job — run the helper.
    static var esPlistXML: String {
        """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0"><dict>
            <key>Label</key><string>\(esCollectorLabel)</string>
            <key>ProgramArguments</key><array>
                <string>\(esCollectorInstallPath)</string>
                <string>--es-collector</string>
            </array>
            <key>RunAtLoad</key><true/>
            <key>KeepAlive</key><true/>
            <key>ThrottleInterval</key><integer>10</integer>
            <key>StandardErrorPath</key><string>/Library/Logs/secure-agent/esd-err.log</string>
        </dict></plist>
        """
    }

    /// The plist, base64-encoded so it can pass through the osascript →
    /// do-shell-script layer without any quoting hazards.
    static var esPlistB64: String {
        Data(esPlistXML.utf8).base64EncodedString()
    }

    /// Runs an AppleScript that shells out with administrator privileges.
    /// Returns false on user-cancel or failure. The password never passes
    /// through our process — Apple's SecurityAgent prompt owns it.
    private func runAppleScriptAdmin(_ script: String) -> Bool {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        p.arguments = ["-e", script]
        p.standardOutput = FileHandle.nullDevice
        let errPipe = Pipe()
        p.standardError = errPipe
        do {
            try p.run()
            p.waitUntilExit()
            if p.terminationStatus != 0 {
                let msg = String(data: errPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
                if !msg.contains("User canceled") {
                    lastError = "collector install failed: \(msg.prefix(160))"
                }
                return false
            }
            return true
        } catch {
            lastError = "collector install failed: \(error.localizedDescription)"
            return false
        }
    }

    // MARK: - CLI symlink

    public func installCLI() throws {
        guard let cliPath = bundledCLIPath else { throw SetupError.notBundled }
        lastError = nil
        let binDir = "\(home)/.local/bin"
        try fm.createDirectory(atPath: binDir, withIntermediateDirectories: true)
        let link = "\(binDir)/secure-agent"
        if fm.fileExists(atPath: link) { try fm.removeItem(atPath: link) }
        try fm.createSymbolicLink(atPath: link, withDestinationPath: cliPath)
    }

    // MARK: - Agent routing (opt-in proxy)

    /// The daemon writes this sourceable snippet on startup; the app only points
    /// the user at it. Sourcing it is the user's own opt-in — we never edit a
    /// shell rc or the system trust store.
    public var agentRoutingSnippetPath: String {
        "\(home)/.config/secure-agent/agent-env.sh"
    }

    public var isAgentRoutingConfigured: Bool {
        fm.fileExists(atPath: agentRoutingSnippetPath)
    }

    public var agentRoutingSourceCommand: String {
        "source ~/.config/secure-agent/agent-env.sh"
    }

    public func copyAgentRoutingCommand() {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(agentRoutingSourceCommand, forType: .string)
    }

    public func revealAgentRoutingSnippet() {
        NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: agentRoutingSnippetPath)])
    }

    // MARK: - Secret registry (fingerprints)

    @Published public private(set) var registeredSecrets: [String] = []
    @Published public private(set) var didRegisterSecrets = false

    /// Ask the daemon to scan the configured sources and register HMAC-only
    /// fingerprints of the user's secrets, activating the highest-precision
    /// detection layer. Never sees or stores plaintext.
    public func registerSecrets() async {
        lastError = nil
        do {
            registeredSecrets = try await DaemonClient().registerSecrets()
            didRegisterSecrets = true
        } catch {
            report(error)
        }
    }

    // MARK: - Guard the classics (opt-in promotion from monitor to prompt)

    public struct GuardClassic: Sendable {
        public let ruleID: String
        public let mode: String
    }

    /// SSH keys, cloud creds, the keychain, and the harness's own enforcement
    /// plane ship `monitor` (quiet by default); this is the user's explicit
    /// opt-in to promote them to `prompt`. No silent deny.
    public nonisolated static let guardClassics: [GuardClassic] = [
        .init(ruleID: "ssh-keys", mode: "prompt"),
        .init(ruleID: "cloud-creds", mode: "prompt"),
        .init(ruleID: "keychain", mode: "prompt"),
        .init(ruleID: "harness-config", mode: "prompt"),
    ]

    @Published public private(set) var didGuardClassics = false

    private var guardModesDir: String { "\(home)/.config/secure-agent" }
    private var guardModesPath: String { "\(guardModesDir)/guard-modes.json" }

    /// The rule ids the guard ships with (mirrors DEFAULT_GUARD_RULES in
    /// secret_guard.py; the hook owns the authoritative copy).
    public static let guardRuleIDs = ["ssh-keys", "cloud-creds", "keychain", "env-files", "shell-rc", "harness-config"]

    /// Current effective mode overrides (empty = the rule ships monitor).
    /// Missing file → empty; corrupt file → the hook fails closed, so report
    /// it here too instead of pretending everything is monitor.
    public func currentGuardModes() -> (modes: [String: String], corrupt: Bool) {
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: guardModesPath)) else {
            return ([:], false) // missing file: everything at shipped defaults
        }
        guard let decoded = try? JSONDecoder().decode([String: String].self, from: data) else {
            return ([:], true)
        }
        return (decoded, false)
    }

    /// Set one rule's mode, atomically, merging over the user's other pins.
    /// The hook reads this file on every guarded tool call — no daemon
    /// round-trip is needed (or possible: the hook is the enforcement point).
    public func setGuardMode(ruleID: String, mode: String) throws {
        guard Self.guardRuleIDs.contains(ruleID) else {
            throw NSError(domain: "SetupManager", code: 1,
                          userInfo: [NSLocalizedDescriptionKey: "unknown guard rule \(ruleID)"])
        }
        guard ["monitor", "prompt", "deny"].contains(mode) else {
            throw NSError(domain: "SetupManager", code: 2,
                          userInfo: [NSLocalizedDescriptionKey: "unknown mode \(mode)"])
        }
        try fm.createDirectory(atPath: guardModesDir, withIntermediateDirectories: true)
        var modes = currentGuardModes().modes
        if mode == "monitor" {
            modes.removeValue(forKey: ruleID) // monitor is the shipped default; don't pin it
        } else {
            modes[ruleID] = mode
        }
        // Atomic: a torn file makes the hook fail closed (deny everything
        // guarded) until fixed.
        try JSONEncoder().encode(modes).write(to: URL(fileURLWithPath: guardModesPath), options: .atomic)
    }

    /// Writes the three classics as `prompt` into `guard-modes.json` — the
    /// same mode-override file the hook reads (`_mode_overrides` in
    /// secret_guard.py). Merges over any existing entries so the user's own
    /// edits are never clobbered.
    public func enableGuardClassics() {
        lastError = nil
        do {
            try fm.createDirectory(atPath: guardModesDir, withIntermediateDirectories: true)
            var modes = currentGuardModes().modes
            for c in Self.guardClassics { modes[c.ruleID] = c.mode }
            // Atomic: a torn guard-modes.json (app killed mid-write) would make
            // the hook's config load fail — and the hook fails CLOSED on
            // corrupt config, so a torn write turns every guarded action into
            // a deny until the file is fixed.
            try JSONEncoder().encode(modes).write(to: URL(fileURLWithPath: guardModesPath), options: .atomic)
            didGuardClassics = true
        } catch {
            report(error)
        }
    }

    // MARK: - Full Disk Access

    public func openFullDiskAccessSettings() {
        NSWorkspace.shared.open(URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles")!)
    }

    /// Reveal the daemon binary in Finder so the user can DRAG it into the
    /// Full Disk Access list — macOS offers no API to add the app ourselves,
    /// and "click + and navigate to a hidden Helpers path" is where users
    /// give up. Drag-and-drop into the FDA list works.
    public func revealDaemonInFinder() {
        guard let path = bundledDaemonPath else { return }
        NSWorkspace.shared.selectFile(path, inFileViewerRootedAtPath: "")
    }

    // MARK: - Uninstall

    /// The single uninstall confirmation, shared by the right-click menu and
    /// Settings — one copy, one button order, one place to evolve.
    /// Returns true when the user confirmed.
    @discardableResult
    public func confirmUninstall() -> Bool {
        let alert = NSAlert()
        alert.messageText = "Uninstall Secure Agent?"
        alert.informativeText = "This stops the background daemon, removes harness hooks, the login item, and the CLI symlink. The app itself and your logs/config are left in place."
        alert.alertStyle = .warning
        alert.addButton(withTitle: "Uninstall")
        alert.addButton(withTitle: "Cancel")
        guard alert.runModal() == .alertFirstButtonReturn else { return false }
        do {
            try uninstallAll()
        } catch {
            report(error)
        }
        Task { await refreshState() }
        return true
    }

    public func uninstallAll() throws {
        lastError = nil
        // Stop the child daemon this app is running.
        DaemonSupervisor.shared.stop()
        // The privileged ES collector is root-installed; remove it too
        // (best-effort: if the admin prompt is cancelled, the helper stays
        // but the app is gone — the plist self-heals nothing without its
        // binary, so a cancelled prompt leaves a harmless, spool-less daemon).
        uninstallESCollector()
        // Tear down any legacy LaunchAgent from an older install.
        let uid = getuid()
        Self.run(["/bin/launchctl", "bootout", "gui/\(uid)/\(Self.daemonLabel)"])
        if fm.fileExists(atPath: daemonPlistPath) {
            try fm.removeItem(atPath: daemonPlistPath)
        }
        if SMAppService.mainApp.status == .enabled {
            try? SMAppService.mainApp.unregister()
        }
        for target in Self.hookTargets {
            for hook in ["secret_guard.py", "injection_scan.py", "activity_log.py"] {
                try? fm.removeItem(atPath: "\(target)/\(hook)")
            }
        }
        try? fm.removeItem(atPath: "\(home)/.local/bin/secure-agent")
    }

    // MARK: - Helpers

    @discardableResult
    private static func run(_ args: [String]) -> Int32 {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: args[0])
        p.arguments = Array(args.dropFirst())
        p.standardOutput = FileHandle.nullDevice
        p.standardError = FileHandle.nullDevice
        do {
            try p.run()
            p.waitUntilExit()
            return p.terminationStatus
        } catch {
            return -1
        }
    }

    public func report(_ error: Error) {
        lastError = error.localizedDescription
    }

    public enum SetupError: LocalizedError {
        case notBundled

        public var errorDescription: String? {
            switch self {
            case .notBundled:
                return "This copy of Secure Agent is not running from its app bundle. Drag Secure Agent.app to /Applications and relaunch it."
            }
        }
    }
}

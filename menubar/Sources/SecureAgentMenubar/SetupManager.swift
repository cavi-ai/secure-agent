import AppKit
import CryptoKit
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
    /// The privileged Endpoint Security collector: a LaunchDaemon shipped in
    /// the bundle (Contents/Library/LaunchDaemons) and registered with
    /// SMAppService.daemon, so macOS attributes it to Secure Agent.
    public nonisolated static let esCollectorLabel = "com.cavi-ai.secure-agent-esd"
    public nonisolated static let esCollectorPlistName = "\(esCollectorLabel).plist"
    /// The collector executable the plist's BundleProgram names.
    public static let esCollectorExecutable = "Contents/MacOS/secure-agent-esd"
    /// Where earlier versions installed the collector outside the bundle;
    /// `removeLegacyESHelper` deletes these.
    static let legacyESPlistPath = "/Library/LaunchDaemons/\(esCollectorPlistName)"
    static let legacyESHelperPath = "/Library/PrivilegedHelperTools/\(esCollectorLabel)"
    static let legacyESHashPath = "/Library/Application Support/secure-agent/esd.binhash"

    @Published public private(set) var isDaemonRunning = false
    @Published public private(set) var areHooksInstalled = false
    /// Nil failure alone is not a pass: no check has run until results exist.
    @Published public private(set) var hookSelfTestFailure: String?
    @Published public private(set) var hookSelfTestRunning = false
    @Published public private(set) var hookProbeResults: [CoverageProbeReceiptModel] = []
    @Published public private(set) var lastError: String?
    /// Local advisor: whether a model server answers on the loopback endpoint
    /// and whether the daemon config has the advisor enabled.
    @Published public private(set) var advisorEnabled = false
    @Published private(set) var advisorPreferences = AdvisorPreferences()
    @Published private(set) var advisorPreferencesError: String?
    @Published public private(set) var systemAgentEnabled = false
    /// system_agent.auto_review: new findings go to the agent's review queue.
    @Published public private(set) var systemAgentAutoReview = false
    @Published private(set) var autoReviewPolicy = AutoReviewPolicy()
    @Published private(set) var autoReviewPolicyAvailable = true
    /// Last-persisted advisor config (mode/endpoint/model) — the Settings
    /// tab's restore source so the advisor persists across restarts.
    @Published public private(set) var advisorPersisted: (mode: String?, endpoint: String?, model: String?) = (nil, nil, nil)
    /// Provider names the operator disabled (from disabled_agents in
    /// config.yaml). Toggling writes the file; the daemon's config watcher
    /// picks it up on its next Load (agents must be statically configured —
    /// tagger rebuilds on restart, not hot).
    @Published public private(set) var disabledAgents: [String] = []

    /// All agent definitions shipped in the daemon's defaults (name → match
    /// strings), for the Providers tab. A test pins this list to
    /// daemon/internal/config/defaults.yaml; the app hosts classified as
    /// infra so their CLI stays the agent (claude-desktop, cursor-ide) are
    /// not toggles.
    public static let knownAgents: [(name: String, matches: [String])] = [
        ("codex", ["codex"]),
        ("cursor", ["cursor"]),
        ("openclaw", ["/.openclaw/"]),
        ("hermes", ["hermes-agent", "/.hermes/"]),
        ("claude", ["claude"]),
        ("opencode", ["opencode", "OpenCode Helper"]),
        ("antigravity", ["antigravity", "Antigravity Helper"]),
        ("pi", ["/bin/pi", "/pi-coding-agent/"]),
        ("qwen-code", ["/bin/qwen", "/qwen-code/"]),
        ("windsurf", ["windsurf"]),
        ("aider", ["aider"]),
        ("codeium", ["codeium"]),
        ("copilot", ["copilot"]),
        ("ollama", ["ollama", "llama-server", "llama.cpp"]),
        ("lm-studio", ["lm studio", "lmstudio"]),
    ]

    /// Toggle one provider. Writes disabled_agents; the daemon's config
    /// watcher applies it within a few seconds.
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
    /// Registration status of the in-bundle collector daemon.
    @Published public private(set) var esServiceStatus: SMAppService.Status = .notRegistered
    /// Whether a collector installed by an earlier version (outside the
    /// bundle, same launchd label) is still present.
    @Published public private(set) var esLegacyHelperInstalled = false
    /// The file-telemetry card's stage, recomputed by `refreshESState`.
    @Published private(set) var esStage: ESStage = .notRegistered
    /// Spool mtime when this app last registered the collector; a later
    /// write proves the registered daemon holds its privacy grant.
    private var esRegisterSpoolMtime: Date?
    private let esService: any ESServiceControl
    private let prefs: UserDefaults
    private let esMemory: ESAutopilotMemory
    private let esPlistCheck: () -> Bool
    private let esOpenPane: (ESSettingsPane) -> Void
    /// The autopilot registers at most once per launch.
    private var esRegisterAttemptedThisLaunch = false
    /// Reads the collector's launchd job; called off the main actor.
    private let esLaunchdProbe: @Sendable () -> LaunchdProbe
    /// This copy's bundle; only the copy in /Applications manages the helper.
    private let appURL: URL
    private let esLocationAllowed: Bool
    /// The launchd probe behind the autopilot's re-register while it runs,
    /// and when the last one started.
    private(set) var esRepairProbe: Task<Void, Never>?
    private var esRepairProbeStarted: Date?
    /// The 1 s poll while a System Settings switch is pending.
    private var esPollTask: Task<Void, Never>?
    /// Telemetry Doctor results, in check order.
    @Published private(set) var doctorChecks: [DoctorCheck] = []
    @Published private(set) var doctorRunning = false
    /// Id of the check whose fix is running.
    @Published private(set) var doctorFixing: String?
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

    /// Tests inject the service, defaults, plist check and pane opener;
    /// the app uses the defaults.
    init(esService: any ESServiceControl = SMAppService.daemon(plistName: SetupManager.esCollectorPlistName),
         defaults: UserDefaults = AppPreferences.shared,
         plistPresent: (() -> Bool)? = nil,
         openPane: ((ESSettingsPane) -> Void)? = nil,
         launchdProbe: (@Sendable () -> LaunchdProbe)? = nil,
         appURL: URL = Bundle.main.bundleURL) {
        self.esService = esService
        self.appURL = appURL
        esLocationAllowed = AppIdentity.isInstalledCopy(appURL)
        esLaunchdProbe = launchdProbe ?? { SetupManager.esLaunchdJob() }
        prefs = defaults
        esMemory = ESAutopilotMemory(
            defaults: defaults,
            build: Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? "")
        esPlistCheck = plistPresent ?? {
            FileManager.default.fileExists(atPath: Bundle.main.bundleURL
                .appendingPathComponent("Contents/Library/LaunchDaemons/\(SetupManager.esCollectorPlistName)").path)
        }
        esOpenPane = openPane ?? { pane in
            MainActor.assumeIsolated { SetupManager.openSettingsPane(pane) }
        }
        esServiceStatus = esService.status
        esLegacyHelperInstalled = fm.fileExists(atPath: Self.legacyESPlistPath)
        esStage = currentESStage()
    }

    // MARK: - State

    public func refreshState() async {
        let status = try? await DaemonClient().fetchStatus()
        if let status, !hookSelfTestRunning {
            hookProbeResults = status.coverage?.probes ?? []
        }
        isDaemonRunning = DaemonSupervisor.shared.isRunning || (status?.running ?? false)
        refreshESState()
        claudeRoutingApplied = ClaudeRouting.isApplied(at: Self.claudeSettingsPath)
        // ALL harnesses must carry the hook — `contains` used to announce
        // "Hooks installed" when only one of three targets had it, leaving the
        // other two unprotected while the wizard claimed otherwise. Claude Code
        // must also have the hooks REGISTERED in settings.json — files on disk
        // alone never run.
        areHooksInstalled = Self.hookTargets.allSatisfy { target in
            fm.fileExists(atPath: "\(target)/secret_guard.py")
        } && claudeHooksRegistered()
          && Self.cursorHooksRegistered(at: Self.cursorHooksPath, command: Self.cursorHookCommand)
        advisorEnabled = Self.advisorConfigIsEnabled(configYAML())
        systemAgentEnabled = Self.systemAgentConfigIsEnabled(configYAML())
        systemAgentAutoReview = Self.systemAgentConfigIsEnabled(configYAML(), key: "auto_review")
        do {
            autoReviewPolicy = try AutoReviewPolicy.read(configYAML())
            autoReviewPolicyAvailable = true
        } catch {
            autoReviewPolicyAvailable = false
            report(error)
        }
        advisorPersisted = Self.advisorConfig(configYAML())
        do {
            advisorPreferences = try AdvisorPreferences.read(configYAML())
            advisorPreferencesError = nil
        } catch { advisorPreferencesError = error.localizedDescription }
        disabledAgents = Self.disabledAgents(configYAML())
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

    /// The chat agent is opt-in. Keep its existing endpoint and model choices
    /// intact when toggling it from Settings; the daemon reloads this live.
    public func setSystemAgentEnabled(_ enabled: Bool) {
        do {
            let updated = Self.systemAgentConfigUpdating(configYAML(), enabled: enabled)
            let dir = (configPath as NSString).deletingLastPathComponent
            try fm.createDirectory(atPath: dir, withIntermediateDirectories: true)
            try updated.write(toFile: configPath, atomically: true, encoding: .utf8)
            systemAgentEnabled = enabled
        } catch {
            report(error)
        }
    }

    /// Automatic review of new findings by the chat agent; applied live.
    public func setSystemAgentAutoReview(_ on: Bool) {
        do {
            let updated = Self.systemAgentConfigUpdating(configYAML(), key: "auto_review", enabled: on)
            let dir = (configPath as NSString).deletingLastPathComponent
            try fm.createDirectory(atPath: dir, withIntermediateDirectories: true)
            try updated.write(toFile: configPath, atomically: true, encoding: .utf8)
            systemAgentAutoReview = on
        } catch {
            report(error)
        }
    }

    /// Change automatic-review eligibility without touching detector settings.
    /// Re-read the current file so other settings and unknown rule IDs survive.
    func setAutoReviewMinimumSeverity(_ severity: Int) {
        updateAutoReviewPolicy { $0.minimumSeverity = severity }
    }

    func setAutoReviewRule(_ rule: String, included: Bool) {
        updateAutoReviewPolicy { policy in
            policy.excludedRules.removeAll { $0 == rule }
            if !included { policy.excludedRules.append(rule) }
        }
    }

    private func updateAutoReviewPolicy(_ change: (inout AutoReviewPolicy) -> Void) {
        do {
            let yaml = fm.fileExists(atPath: configPath)
                ? try String(contentsOfFile: configPath, encoding: .utf8) : ""
            var policy = try AutoReviewPolicy.read(yaml)
            change(&policy)
            let updated = try policy.updating(yaml)
            let dir = (configPath as NSString).deletingLastPathComponent
            try fm.createDirectory(atPath: dir, withIntermediateDirectories: true)
            try updated.write(toFile: configPath, atomically: true, encoding: .utf8)
            autoReviewPolicy = policy
            autoReviewPolicyAvailable = true
        } catch {
            report(error)
        }
    }

    public nonisolated static func systemAgentConfigIsEnabled(_ yaml: String, key: String = "enabled") -> Bool {
        var inBlock = false
        for line in yaml.split(separator: "\n", omittingEmptySubsequences: false) {
            let s = String(line)
            if s.hasPrefix("system_agent:") { inBlock = true; continue }
            if inBlock && !s.hasPrefix(" ") && !s.hasPrefix("#") && !s.isEmpty { inBlock = false }
            if inBlock && s.trimmingCharacters(in: .whitespaces).hasPrefix("\(key):") {
                let value = s.trimmingCharacters(in: .whitespaces).dropFirst(key.count + 1)
                    .split(separator: "#", maxSplits: 1).first.map(String.init) ?? ""
                return value.trimmingCharacters(in: .whitespaces) == "true"
            }
        }
        return false
    }

    public nonisolated static func systemAgentConfigUpdating(_ yaml: String, key: String = "enabled", enabled: Bool) -> String {
        let value = enabled ? "true" : "false"
        var lines = yaml.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
        guard let start = lines.firstIndex(where: { $0.hasPrefix("system_agent:") }) else {
            var base = yaml
            if !base.isEmpty && !base.hasSuffix("\n") { base += "\n" }
            return base + "system_agent:\n  \(key): \(value)\n"
        }
        let end = (start + 1..<lines.count).first {
            let line = lines[$0]
            return !line.isEmpty && !line.hasPrefix(" ") && !line.hasPrefix("#")
        } ?? lines.count
        for i in start + 1..<end where lines[i].trimmingCharacters(in: .whitespaces).hasPrefix("\(key):") {
            let indent = String(lines[i].prefix(while: { $0 == " " }))
            lines[i] = "\(indent)\(key): \(value)"
            return lines.joined(separator: "\n")
        }
        lines.insert("  \(key): \(value)", at: start + 1)
        return lines.joined(separator: "\n")
    }

    /// Flip advisor.enabled in config.yaml. Line-based and deliberately
    /// narrow: config.yaml is user-owned, so we rewrite only the enabled line
    /// inside the advisor block, or append the whole block when absent.
    /// Writes are atomic — a torn config would be a loud daemon error.
    public func setAdvisorEnabled(_ enabled: Bool) {
        do {
            let updated = try Self.advisorConfigUpdating(configYAML(), enabled: enabled)
            let dir = (configPath as NSString).deletingLastPathComponent
            try fm.createDirectory(atPath: dir, withIntermediateDirectories: true)
            try updated.write(toFile: configPath, atomically: true, encoding: .utf8)
            advisorEnabled = enabled
            advisorNote = "Automatic analysis " + (enabled ? "enabled" : "disabled") + " — applied live (daemon hot-reloads config)."
        } catch {
            report(error)
        }
    }

    public enum AdvisorMode: String, Sendable {
        case managed, existing
    }

    // MARK: - Inspection proxy (web console)

    /// Flip proxy_enabled in config.yaml. Line-based and deliberately narrow,
    /// same contract as the advisor helpers: rewrite the TOP-LEVEL key when
    /// present (never an indented or commented lookalike), append it
    /// otherwise, preserve every other byte of the user's file.
    public nonisolated static func proxyEnabledUpdating(_ yaml: String, enabled: Bool) -> String {
        let value = enabled ? "true" : "false"
        let lines = yaml.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
        var out = lines
        var replaced = false
        for i in lines.indices {
            let line = lines[i]
            guard !line.hasPrefix(" "), !line.hasPrefix("\t"), !line.hasPrefix("#") else { continue }
            if line.trimmingCharacters(in: .whitespaces).hasPrefix("proxy_enabled:") {
                out[i] = "proxy_enabled: \(value)"
                replaced = true
            }
        }
        if replaced { return out.joined(separator: "\n") }
        var base = yaml
        if !base.isEmpty && !base.hasSuffix("\n") { base += "\n" }
        return base + """
        # Loopback inspection proxy (127.0.0.1): serves the web console and
        # inspects agent egress for secret leaks / prompt injection.
        proxy_enabled: \(value)

        """
    }

    /// Write proxy_enabled; the daemon starts the proxy at boot only, so the
    /// caller is responsible for bouncing the daemon afterwards.
    public func setProxyEnabled(_ enabled: Bool) {
        do {
            let updated = Self.proxyEnabledUpdating(configYAML(), enabled: enabled)
            let dir = (configPath as NSString).deletingLastPathComponent
            try fm.createDirectory(atPath: dir, withIntermediateDirectories: true)
            try updated.write(toFile: configPath, atomically: true, encoding: .utf8)
        } catch {
            report(error)
        }
    }

    /// Write the full advisor block for one of the two first-class paths:
    /// managed (daemon spawns the model server; no endpoint in the file) or
    /// existing (loopback endpoint + model from the discovery dropdowns).
    /// Atomic write; the daemon applies changes live.
    public func setAdvisorConfig(mode: AdvisorMode, endpoint: String?, model: String) {
        do {
            let updated = try Self.advisorConfigSetting(configYAML(), mode: mode, endpoint: endpoint, model: model)
            let dir = (configPath as NSString).deletingLastPathComponent
            try fm.createDirectory(atPath: dir, withIntermediateDirectories: true)
            try updated.write(toFile: configPath, atomically: true, encoding: .utf8)
            advisorEnabled = true
            advisorNote = "Analysis model configured (\(mode.rawValue)) — applied live (daemon hot-reloads config)."
        } catch {
            report(error)
        }
    }

    /// The advisor config a recommendation writes: an installed model runs on
    /// the server holding it; a catalog model is run by the daemon itself.
    public nonisolated static func advisorChoice(for r: ModelRecommendationModel) -> (mode: AdvisorMode, endpoint: String?, model: String) {
        if r.source == "installed", let ep = r.endpoint {
            return (.existing, ep, r.modelID)
        }
        return (.managed, nil, r.modelID)
    }

    /// Configure and enable the advisor with a recommended model.
    public func applyRecommendation(_ r: ModelRecommendationModel) {
        let c = Self.advisorChoice(for: r)
        setAdvisorConfig(mode: c.mode, endpoint: c.endpoint, model: c.model)
    }

    /// Update model fields without discarding timeout, classifier, debug or future fields.
    public nonisolated static func advisorConfigSetting(_ yaml: String, mode: AdvisorMode, endpoint: String?, model: String) throws -> String {
        try AdvisorPreferences.settingModel(yaml, managed: mode == .managed, endpoint: endpoint, model: model)
    }

    func saveAdvisorPreferences(_ preferences: AdvisorPreferences) throws {
        let updated = try preferences.updating(configYAML())
        try fm.createDirectory(atPath: (configPath as NSString).deletingLastPathComponent, withIntermediateDirectories: true)
        try updated.write(toFile: configPath, atomically: true, encoding: .utf8)
        advisorPreferences = preferences
        advisorPreferencesError = nil
        advisorNote = "Advisor settings saved — applied live."
    }

    func openAdvisorLog() {
        let logURL = URL(fileURLWithPath: NSHomeDirectory() + "/Library/Logs/secure-agent/daemon-err.log")
        guard fm.fileExists(atPath: logURL.path) else {
            advisorNote = "No daemon log yet. Start Secure Agent, then open the log."
            return
        }
        if !NSWorkspace.shared.open(logURL) {
            advisorNote = "The log could not be opened. It is at ~/Library/Logs/secure-agent/daemon-err.log."
        }
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
        var endpoint: String?
        var model: String?
        var managed: Bool?
        var hasExistingConfig = false
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
                hasExistingConfig = hasExistingConfig || endpoint?.isEmpty == false
            } else if t.hasPrefix("model:") {
                model = t.replacingOccurrences(of: "model:", with: "")
                    .trimmingCharacters(in: .whitespaces)
                    .replacingOccurrences(of: "\"", with: "")
                hasExistingConfig = hasExistingConfig || model?.isEmpty == false
            }
        }
        // The canonical existing-server writer omits managed; the daemon
        // treats that absence as unmanaged rather than unconfigured.
        let m = managed.map { $0 ? "managed" : "existing" }
            ?? (hasExistingConfig ? "existing" : nil)
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
    public nonisolated static func advisorConfigUpdating(_ yaml: String, enabled: Bool) throws -> String {
        try AdvisorPreferences.settingEnabled(yaml, enabled: enabled)
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

    /// Hook scripts shipped in a bundled hooks directory (tests excluded), and
    /// guard-rules.json, which secret_guard.py loads from its own directory.
    nonisolated static func hookFileNames(in dir: String) throws -> [String] {
        try FileManager.default.contentsOfDirectory(atPath: dir)
            .filter { ($0.hasSuffix(".py") && !$0.hasPrefix("test_")) || $0 == "guard-rules.json" }
    }

    public func installHooks() throws {
        guard let srcDir = bundledHooksDir else { throw SetupError.notBundled }
        lastError = nil
        let hooks = try Self.hookFileNames(in: srcDir)
        for target in Self.hookTargets {
            try fm.createDirectory(atPath: target, withIntermediateDirectories: true)
            for hook in hooks {
                let dst = "\(target)/\(hook)"
                if fm.fileExists(atPath: dst) { try fm.removeItem(atPath: dst) }
                try fm.copyItem(atPath: "\(srcDir)/\(hook)", toPath: dst)
            }
        }
        // Copying the script is not enough: Claude Code runs hooks only when
        // settings.json registers them. The audited gap was exactly this —
        // files copied, nothing registered, guard never ran.
        try registerClaudeHooks()
        try Self.registerCursorHooks(at: Self.cursorHooksPath, command: Self.cursorHookCommand)
    }

    /// Brings already-installed hook copies up to the bundled versions so an
    /// app update reaches the scripts the harnesses run. Only targets that
    /// already carry the guard are refreshed; settings.json is not touched.
    public func refreshInstalledHooks() {
        guard let srcDir = bundledHooksDir else { return }
        for target in Self.hookTargets where fm.fileExists(atPath: "\(target)/secret_guard.py") {
            do {
                let refreshed = try Self.refreshInstalledHooks(bundledDir: srcDir, installedDir: target)
                if !refreshed.isEmpty {
                    NSLog("[secure-agent] refreshed hooks in \(target): \(refreshed.joined(separator: ", "))")
                }
            } catch {
                NSLog("[secure-agent] hook refresh failed for \(target): \(error.localizedDescription)")
            }
        }
    }

    /// Overwrites each installed hook whose SHA-256 differs from the bundled
    /// copy and creates missing ones; identical files are left untouched.
    /// Returns the names written.
    @discardableResult
    nonisolated static func refreshInstalledHooks(bundledDir: String, installedDir: String) throws -> [String] {
        let fm = FileManager.default
        var refreshed: [String] = []
        for hook in try hookFileNames(in: bundledDir).sorted() {
            let src = "\(bundledDir)/\(hook)"
            let dst = "\(installedDir)/\(hook)"
            if let installed = fileSHA256(dst), installed == fileSHA256(src) { continue }
            if fm.fileExists(atPath: dst) { try fm.removeItem(atPath: dst) }
            try fm.copyItem(atPath: src, toPath: dst)
            refreshed.append(hook)
        }
        return refreshed
    }

    private nonisolated static func fileSHA256(_ path: String) -> String? {
        guard let data = FileManager.default.contents(atPath: path) else { return nil }
        return SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    // MARK: - Harness hook registration (Claude Code settings.json)

    public static var claudeSettingsPath: String { NSHomeDirectory() + "/.claude/settings.json" }

    /// The command Claude Code runs for guarded tool calls.
    public static var claudeHookCommand: String {
        "python3 \(NSHomeDirectory())/.claude/hooks/secret_guard.py"
    }

    /// Merge PreToolUse + PostToolUse entries into ~/.claude/settings.json.
    /// Merge, never clobber: the user's other hooks and settings stay
    /// untouched. Backup first, atomic write — a torn settings file would
    /// break the user's whole harness, not just us. Idempotent.
    public func registerClaudeHooks() throws {
        try Self.registerClaudeHooks(at: Self.claudeSettingsPath, command: Self.claudeHookCommand)
    }

    /// Path-parameterized core of registerClaudeHooks (tests use temp files).
    nonisolated static func registerClaudeHooks(at path: String, command: String) throws {
        let fm = FileManager.default
        var root: [String: Any] = [:]
        if let data = fm.contents(atPath: path), !data.isEmpty {
            guard let parsed = try? JSONSerialization.jsonObject(with: data),
                  let dict = parsed as? [String: Any] else {
                throw NSError(domain: "SetupManager", code: 3,
                              userInfo: [NSLocalizedDescriptionKey: "~/.claude/settings.json is not valid JSON — not touching it; fix or back it up first"])
            }
            root = dict
            // Backup before any mutation of a file we don't own.
            try? data.write(to: URL(fileURLWithPath: path + ".bak-secure-agent"), options: .atomic)
        }
        var hooks = root["hooks"] as? [String: Any] ?? [:]
        for eventName in ["PreToolUse", "PostToolUse"] {
            var groups = hooks[eventName] as? [[String: Any]] ?? []
            if !Self.groupsContainGuard(groups) {
                groups.append([
                    "matcher": "*",
                    "hooks": [["type": "command", "command": command]],
                ])
            }
            hooks[eventName] = groups
        }
        root["hooks"] = hooks
        try fm.createDirectory(atPath: (path as NSString).deletingLastPathComponent, withIntermediateDirectories: true)
        let data = try JSONSerialization.data(withJSONObject: root, options: [.prettyPrinted, .sortedKeys])
        try data.write(to: URL(fileURLWithPath: path), options: .atomic)
    }

    /// Whether Claude Code's settings reference the guard for both events.
    public func claudeHooksRegistered() -> Bool {
        Self.claudeHooksRegistered(at: Self.claudeSettingsPath)
    }

    nonisolated static func claudeHooksRegistered(at path: String) -> Bool {
        guard let data = FileManager.default.contents(atPath: path),
              let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let hooks = root["hooks"] as? [String: Any] else { return false }
        return ["PreToolUse", "PostToolUse"].allSatisfy {
            Self.groupsContainGuard(hooks[$0] as? [[String: Any]] ?? [])
        }
    }

    /// Remove our registrations (uninstall), leaving other hooks untouched.
    public func unregisterClaudeHooks() {
        Self.unregisterClaudeHooks(at: Self.claudeSettingsPath)
    }

    nonisolated static func unregisterClaudeHooks(at path: String) {
        guard let data = FileManager.default.contents(atPath: path),
              var root = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              var hooks = root["hooks"] as? [String: Any] else { return }
        for eventName in ["PreToolUse", "PostToolUse"] {
            let groups = (hooks[eventName] as? [[String: Any]] ?? []).compactMap { group -> [String: Any]? in
                let kept = (group["hooks"] as? [[String: Any]] ?? []).filter { h in
                    guard let cmd = h["command"] as? String else { return true }
                    return !cmd.contains("/.claude/hooks/secret_guard.py")
                }
                if kept.isEmpty { return nil }
                var g = group
                g["hooks"] = kept
                return g
            }
            hooks[eventName] = groups
        }
        root["hooks"] = hooks
        if let out = try? JSONSerialization.data(withJSONObject: root, options: [.prettyPrinted, .sortedKeys]) {
            try? out.write(to: URL(fileURLWithPath: path), options: .atomic)
        }
    }

    private nonisolated static func groupsContainGuard(_ groups: [[String: Any]]) -> Bool {
        for group in groups {
            for h in group["hooks"] as? [[String: Any]] ?? [] {
                if let cmd = h["command"] as? String, cmd.contains("/.claude/hooks/secret_guard.py") {
                    return true
                }
            }
        }
        return false
    }

    // MARK: - Cursor native tool hooks

    public static var cursorHooksPath: String { NSHomeDirectory() + "/.cursor/hooks.json" }
    public static var cursorHookCommand: String {
        let path = NSHomeDirectory() + "/.cursor/hooks/secret_guard.py"
        return "python3 '" + path.replacingOccurrences(of: "'", with: "'\"'\"'") + "'"
    }

    /// Cursor's native pre/post hooks cover all tool types. Keep user hooks
    /// and settings, reject unsupported schemas, and back up before mutation.
    nonisolated static func cursorHookConfig(at path: String) throws -> ([String: Any], Data?) {
        let fm = FileManager.default
        guard fm.fileExists(atPath: path) else { return (["version": 1, "hooks": [:]], nil) }
        let data = try Data(contentsOf: URL(fileURLWithPath: path))
        guard let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let version = root["version"] as? NSNumber, version == 1,
              CFGetTypeID(version) != CFBooleanGetTypeID(),
              let hooks = root["hooks"] as? [String: Any],
              ["preToolUse", "postToolUse"].allSatisfy({ hooks[$0] == nil || hooks[$0] is [[String: Any]] }) else {
            throw NSError(domain: "SetupManager", code: 4,
                          userInfo: [NSLocalizedDescriptionKey: "Cursor hooks.json has an invalid or unsupported schema; it was left unchanged."])
        }
        return (root, data)
    }

    nonisolated static func registerCursorHooks(at path: String, command: String) throws {
        var (root, original) = try cursorHookConfig(at: path)
        var hooks = root["hooks"] as! [String: Any]
        var changed = false
        for event in ["preToolUse", "postToolUse"] {
            var entries = hooks[event] as? [[String: Any]] ?? []
            if !entries.contains(where: { ($0["command"] as? String) == command && $0["matcher"] == nil
                    && ($0["type"] == nil || ($0["type"] as? String) == "command") }) {
                entries.append(["command": command])
                hooks[event] = entries
                changed = true
            }
        }
        guard changed else { return }
        let fm = FileManager.default
        try fm.createDirectory(atPath: (path as NSString).deletingLastPathComponent, withIntermediateDirectories: true)
        // Preserve the first pre-install snapshot; a repeated install must not
        // replace it with a snapshot containing our own registrations.
        if let original, !fm.fileExists(atPath: path + ".bak-secure-agent") {
            try original.write(to: URL(fileURLWithPath: path + ".bak-secure-agent"), options: .atomic)
        }
        root["hooks"] = hooks
        let data = try JSONSerialization.data(withJSONObject: root, options: [.prettyPrinted, .sortedKeys])
        try data.write(to: URL(fileURLWithPath: path), options: .atomic)
    }

    nonisolated static func cursorHooksRegistered(at path: String, command: String) -> Bool {
        guard let (root, _) = try? cursorHookConfig(at: path),
              let hooks = root["hooks"] as? [String: Any] else { return false }
        return ["preToolUse", "postToolUse"].allSatisfy { event in
            (hooks[event] as? [[String: Any]] ?? []).contains {
                ($0["command"] as? String) == command && $0["matcher"] == nil
                    && ($0["type"] == nil || ($0["type"] as? String) == "command")
            }
        }
    }

    nonisolated static func unregisterCursorHooks(at path: String, command: String) throws {
        guard FileManager.default.fileExists(atPath: path) else { return }
        var (root, _) = try cursorHookConfig(at: path)
        var hooks = root["hooks"] as! [String: Any]
        for event in ["preToolUse", "postToolUse"] {
            if let entries = hooks[event] as? [[String: Any]] {
                hooks[event] = entries.filter { ($0["command"] as? String) != command }
            }
        }
        root["hooks"] = hooks
        let data = try JSONSerialization.data(withJSONObject: root, options: [.prettyPrinted, .sortedKeys])
        try data.write(to: URL(fileURLWithPath: path), options: .atomic)
    }

    /// Run the self-test and publish the outcome to the wizard UI.
    public func runHookSelfTest() async {
        guard !hookSelfTestRunning else { return }
        hookSelfTestRunning = true
        hookProbeResults = []
        defer { hookSelfTestRunning = false }
        hookSelfTestFailure = await selfTestHooks()
    }

    /// Fire a synthetic guarded tool call through the installed hook and check
    /// it answers. A green check here means: python3 present, hook executable,
    /// protocol intact — the whole chain a silent failure would otherwise hide.
    /// Returns nil on success, or a human-readable reason on failure.
    public func selfTestHooks() async -> String? {
        let client = DaemonClient()
        let home = fm.homeDirectoryForCurrentUser.path
        let harnesses = ["claude", "cursor"].filter { fm.fileExists(atPath: "\(home)/.\($0)/hooks/secret_guard.py") }
        guard !harnesses.isEmpty else { return "Install Claude or Cursor hooks to check the guard path. Other agents retain their supported observational coverage." }
        var failures: [String] = []
        for harness in harnesses {
            do {
                let challenge = try await client.startCoverageProbe(harness: harness)
                var env = ProcessInfo.processInfo.environment
                env["SECURE_AGENT_PROBE_ID"] = challenge.id
                env["SECURE_AGENT_HARNESS"] = harness
                env["SECURE_AGENT_SOCK"] = client.socketPath
                let failure = await Self.selfTestHook(at: challenge.hookPath, environment: env)
                let receipt = try await client.finishCoverageProbe(id: challenge.id, passed: failure == nil)
                hookProbeResults.append(receipt)
                if let failure { failures.append("\(harness): \(failure)") }
                else if receipt.state != "passed" { failures.append("\(harness): \(receipt.detail)") }
            } catch {
                failures.append("\(harness): the daemon check could not complete. Restart Secure Agent and recheck installed hooks.")
            }
        }
        return failures.isEmpty ? nil : failures.joined(separator: "\n")
    }

    /// Runs the guard at hook with a harmless Read and checks it answers allow.
    /// environment replaces the inherited one when set (tests point the
    /// activity log at a temporary file).
    nonisolated static func selfTestHook(at hook: String, environment: [String: String]? = nil) async -> String? {
        let probeID = environment?["SECURE_AGENT_PROBE_ID"]
        let path = probeID.map { "/secure-agent-probe/\($0)/inert.txt" } ?? "/tmp/secure-agent-self-test-allow.txt"
        var payload: [String: Any] = ["hook_event_name": "PreToolUse", "tool_name": "Read", "tool_input": ["file_path": path]]
        if let probeID { payload["secure_agent_probe"] = probeID }
        guard let stdinData = try? JSONSerialization.data(withJSONObject: payload) else { return "internal: payload encoding" }

        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        p.arguments = ["python3", hook]
        if let environment {
            p.environment = environment
        }
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
        let errText = String(data: await errData, encoding: .utf8) ?? ""
        let out = String(data: await outData, encoding: .utf8) ?? ""
        guard p.terminationStatus == 0 else { return "hook exited unsuccessfully; the check did not pass" }
        guard let json = try? JSONSerialization.jsonObject(with: Data(out.utf8)) as? [String: Any] else {
            if let lastError = errText.split(separator: "\n").last {
                return "hook produced no JSON: \(lastError)"
            }
            return "hook produced no JSON (python3 missing or hook crashed)"
        }
        if let probeID {
            return json["permission"] as? String == "deny" && json["secure_agent_probe"] as? String == probeID
                ? nil : "hook did not return the daemon's inert deny receipt"
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

    /// Whether the collector daemon is registered and allowed to run
    /// (regardless of whether it holds its privacy grant yet).
    public var esCollectorDaemonInstalled: Bool {
        esService.status == .enabled
    }

    /// Whether the spool has data at all (some collector build wrote it).
    public var isESCollectorInstalled: Bool {
        guard let attrs = try? FileManager.default.attributesOfItem(atPath: Self.esSpoolPath),
              let size = attrs[.size] as? UInt64, size > 0 else { return false }
        return true
    }

    /// Whether the collector holds its privacy grant: the spool has data
    /// and, when this app registered the collector, was written after that.
    public var esSpoolFlowing: Bool {
        isESCollectorInstalled &&
            Self.regrantResolved(installSpoolMtime: esRegisterSpoolMtime, currentSpoolMtime: esSpoolMtime())
    }

    /// Whether the collector executable is newer than the last spool write:
    /// an ad-hoc signed build's privacy grant is bound to the build that
    /// received it, so a replaced executable stays dark until re-granted.
    public var esHelperReplaced: Bool {
        guard let spool = esSpoolMtime(), let helper = esHelperMtime() else { return false }
        return !Self.regrantResolved(installSpoolMtime: helper, currentSpoolMtime: spool)
    }

    /// The privileged collector's spool, written as root and readable here.
    public nonisolated static let esSpoolPath = "/var/db/secure-agent/es-spool.jsonl"

    private func esSpoolMtime() -> Date? {
        (try? fm.attributesOfItem(atPath: Self.esSpoolPath))?[.modificationDate] as? Date
    }

    private func esHelperMtime() -> Date? {
        let path = Bundle.main.bundleURL.appendingPathComponent(Self.esCollectorExecutable).path
        return (try? fm.attributesOfItem(atPath: path))?[.modificationDate] as? Date
    }

    /// The grant is proven once the spool is written after `installSpoolMtime`.
    public nonisolated static func regrantResolved(installSpoolMtime: Date?, currentSpoolMtime: Date?) -> Bool {
        guard let current = currentSpoolMtime else { return false }
        guard let installed = installSpoolMtime else { return true }
        return current > installed
    }

    /// The card's Enable: clears the user's Remove and registers the
    /// in-bundle collector daemon.
    public func installESCollector() throws {
        lastError = nil
        esMemory.userDisabled = false
        try registerESService()
        refreshESState()
    }

    /// A first registration leaves the daemon awaiting the user's approval in
    /// Login Items; that is the expected outcome, not an error.
    private func registerESService() throws {
        guard esLocationAllowed else { throw SetupError.notInstalledCopy }
        esRegisterSpoolMtime = esSpoolMtime()
        do {
            try esService.register()
        } catch {
            esServiceStatus = esService.status
            guard esServiceStatus == .requiresApproval else { throw error }
        }
        esServiceStatus = esService.status
    }

    /// Whether the bundle carries the collector's launchd plist.
    var esPlistPresent: Bool { esPlistCheck() }

    private func currentESStage() -> ESStage {
        if !esLocationAllowed { return .wrongLocation }
        if esLegacyHelperInstalled { return .legacyInstalled }
        return esCardState(status: esServiceStatus, plistPresent: esPlistPresent,
                           tccGranted: esSpoolFlowing, helperReplaced: esHelperReplaced)
    }

    /// Re-reads the collector's registration, recomputes the card stage, runs
    /// one autopilot step, and starts or stops the 1 s poll. Runs at launch,
    /// on every `refreshState`, and on each poll tick.
    public func refreshESState() {
        // Assign only on change: the poll ticks every second and every
        // @Published write re-renders each observing view.
        let status = esService.status
        if status != esServiceStatus { esServiceStatus = status }
        let legacy = fm.fileExists(atPath: Self.legacyESPlistPath)
        if legacy != esLegacyHelperInstalled { esLegacyHelperInstalled = legacy }
        let stage = currentESStage()
        if stage != esStage { esStage = stage }
        runESAutopilot()
        repairStuckESJob()
        manageESPoll()
    }

    /// Executes `ESAutopilot.decide`. Each action flips the flag that
    /// suppresses it (attempted this launch, pane opened for this build), so
    /// the follow-up step after a registration terminates.
    private func runESAutopilot() {
        let action = ESAutopilot.decide(stage: esStage, userDisabled: esMemory.userDisabled,
                                        attemptedThisLaunch: esRegisterAttemptedThisLaunch,
                                        panesOpenedForBuild: esMemory.panesOpenedForBuild)
        switch action {
        case .none:
            return
        case .register:
            esRegisterAttemptedThisLaunch = true
            do {
                try registerESService()
            } catch {
                lastError = "file telemetry: \(error.localizedDescription)"
            }
            esStage = currentESStage()
            runESAutopilot()
        case .open(let pane):
            esMemory.markOpened(pane)
            esOpenPane(pane)
        }
    }

    /// Re-registers once per launch when the service is enabled but launchd
    /// will not start its job. The launchd probe runs off the main actor, one
    /// at a time, at most every 30 s.
    private func repairStuckESJob() {
        guard esLocationAllowed, esRepairProbe == nil, !esRegisterAttemptedThisLaunch, !esMemory.userDisabled,
              esServiceStatus == .enabled,
              esRepairProbeStarted.map({ Date().timeIntervalSince($0) >= 30 }) ?? true else { return }
        esRepairProbeStarted = Date()
        let probe = esLaunchdProbe
        esRepairProbe = Task { [weak self] in
            let job = await Task.detached { probe() }.value
            guard let self else { return }
            self.esRepairProbe = nil
            if ESAutopilot.needsReregister(serviceStatus: self.esService.status,
                                           userDisabled: self.esMemory.userDisabled,
                                           attemptedThisLaunch: self.esRegisterAttemptedThisLaunch,
                                           launchd: job) {
                self.reregisterESService()
            }
        }
    }

    /// Unregisters and registers the collector again: the Doctor's
    /// Re-register, the autopilot's repair and `secure-agent://telemetry/repair`.
    /// Counts as this launch's registration attempt.
    public func reregisterESService() {
        guard esLocationAllowed else {
            report(SetupError.notInstalledCopy)
            return
        }
        esRegisterAttemptedThisLaunch = true
        do {
            try? esService.unregister()
            try installESCollector()
        } catch { report(error) }
    }

    /// Polls once a second while the stage waits on a System Settings switch
    /// and the user has not removed file telemetry; stops otherwise.
    private func manageESPoll() {
        let wanted = esStage.awaitsUser && !esMemory.userDisabled
        if wanted, esPollTask == nil {
            esPollTask = Task { [weak self] in
                while !Task.isCancelled {
                    try? await Task.sleep(nanoseconds: 1_000_000_000)
                    guard let self, self.esPollTask != nil else { return }
                    self.refreshESState()
                }
            }
        } else if !wanted, let task = esPollTask {
            task.cancel()
            esPollTask = nil
        }
    }

    /// The autopilot's pane opener: the pane plus a notification naming the
    /// switch to flip.
    private static func openSettingsPane(_ pane: ESSettingsPane) {
        switch pane {
        case .loginItems:
            SMAppService.openSystemSettingsLoginItems()
            NotificationManager.shared.sendSetupNotification(
                "Turn on Secure Agent's file-telemetry service in Login Items",
                identifier: "secure-agent.setup.login-items")
        case .fullDiskAccess:
            if let url = URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles") {
                NSWorkspace.shared.open(url)
            }
            NotificationManager.shared.sendSetupNotification(
                "Turn on Secure Agent in Full Disk Access",
                identifier: "secure-agent.setup.full-disk-access")
        }
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

    /// Deep-link System Settings → Full Disk Access, where the collector
    /// appears as Secure Agent.
    public func openESPermissions() {
        if let url = URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles") {
            NSWorkspace.shared.open(url)
        }
    }

    /// Opens System Settings → Login Items, where a registered daemon awaits
    /// approval.
    public func openESLoginItems() {
        SMAppService.openSystemSettingsLoginItems()
    }

    /// Unregisters the collector daemon. Also called by uninstallAll.
    public func uninstallESCollector() throws {
        lastError = nil
        try esService.unregister()
        esServiceStatus = esService.status
    }

    /// The card's Remove: records the user's choice so the autopilot stops
    /// registering, then unregisters.
    public func removeESCollector() throws {
        esMemory.userDisabled = true
        defer { refreshESState() }
        try uninstallESCollector()
    }

    /// Whether the user removed file telemetry (cleared by Enable).
    var esUserDisabled: Bool { esMemory.userDisabled }

    /// Removes the collector an earlier version installed outside the bundle
    /// (it shares the launchd label with the in-bundle daemon): boot out the
    /// job, delete its plist, helper binary and integrity hash. The only
    /// admin prompt in the app.
    public func removeLegacyESHelper() {
        lastError = nil
        let plist = Self.legacyESPlistPath
        let shell =
            "launchctl bootout system '\(plist)' 2>/dev/null;" +
            " rm -f '\(plist)' '\(Self.legacyESHelperPath)' '\(Self.legacyESHashPath)'"
        let script = "do shell script \(shellAppleScriptLiteral(shell)) with administrator privileges"
        _ = runAppleScriptAdmin(script)
        esLegacyHelperInstalled = fm.fileExists(atPath: plist)
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
                    lastError = "old helper removal failed: \(msg.prefix(160))"
                }
                return false
            }
            return true
        } catch {
            lastError = "old helper removal failed: \(error.localizedDescription)"
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
            return ([:], fm.fileExists(atPath: guardModesPath))
        }
        guard let decoded = try? JSONDecoder().decode([String: String].self, from: data) else {
            return ([:], true)
        }
        guard decoded.values.allSatisfy({ ["monitor", "prompt", "deny"].contains($0) }) else { return ([:], true) }
        return (decoded, false)
    }

    /// Set one rule's mode, atomically, merging over the user's other pins.
    /// The hook reads this file on every guarded tool call — no daemon
    /// round-trip is needed (or possible: the hook is the enforcement point).
    public func setGuardMode(ruleID: String, mode: String) throws {
        guard ruleID.range(of: "^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$", options: .regularExpression) != nil else {
            throw NSError(domain: "SetupManager", code: 1,
                          userInfo: [NSLocalizedDescriptionKey: "unknown guard rule \(ruleID)"])
        }
        guard ["monitor", "prompt", "deny"].contains(mode) else {
            throw NSError(domain: "SetupManager", code: 2,
                          userInfo: [NSLocalizedDescriptionKey: "unknown mode \(mode)"])
        }
        try fm.createDirectory(atPath: guardModesDir, withIntermediateDirectories: true)
        let current = currentGuardModes()
        guard !current.corrupt else {
            throw NSError(domain: "SetupManager", code: 3,
                          userInfo: [NSLocalizedDescriptionKey: "guard-modes.json is unreadable; repair it before editing"])
        }
        var modes = current.modes
        modes[ruleID] = mode // custom rules may ship prompt/deny; monitor must be explicit
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

    // MARK: - Telemetry Doctor

    /// The collector's stderr log (StandardErrorPath in its plist).
    nonisolated static let esHelperLogPath = "/var/log/secure-agent-esd.log"

    /// Collects the Doctor's facts: signatures, the launchd job, the helper's
    /// log tail and the spool on disk (off the main actor), then the daemon's
    /// `/status` and `/doctor`.
    func collectTelemetryFacts() async -> TelemetryFacts {
        let appPath = appURL.path
        let helperPath = appURL.appendingPathComponent(Self.esCollectorExecutable).path
        let thisCopy = appURL.resolvingSymlinksInPath().path
        let otherCopies = NSWorkspace.shared.urlsForApplications(withBundleIdentifier: AppIdentity.bundleIdentifier)
            .map { $0.resolvingSymlinksInPath().path }
            .filter { $0 != thisCopy }
        let probe = await Task.detached { () -> (CodeSignature?, CodeSignature?, LaunchdProbe, String?, Date?) in
            let app = CodeSignature.parse(Self.capture(["/usr/bin/codesign", "-dv", appPath]))
            let helper = CodeSignature.parse(Self.capture(["/usr/bin/codesign", "-dv", helperPath]))
            let job = Self.esLaunchdJob()
            let logLine = TelemetryDoctor.lastLine(ofFileAt: Self.esHelperLogPath)
            let mtime = (try? FileManager.default.attributesOfItem(atPath: Self.esSpoolPath))?[.modificationDate] as? Date
            return (app, helper, job, logLine, mtime)
        }.value
        let client = DaemonClient()
        let status = try? await client.fetchStatus()
        let doctor = try? await client.fetchDoctor()
        return TelemetryFacts(
            now: Date(), appSignature: probe.0, helperSignature: probe.1,
            plistPresent: esPlistPresent, serviceStatus: esService.status, launchd: probe.2,
            helperLogLastLine: probe.3, spoolMtime: probe.4, esService: status?.esService,
            legacyInstalled: fm.fileExists(atPath: Self.legacyESPlistPath), daemonChecks: doctor?.checks,
            locationAllowed: esLocationAllowed, otherCopies: otherCopies)
    }

    /// Runs the Doctor once and publishes its checks.
    public func runDoctor() async {
        doctorRunning = true
        defer { doctorRunning = false }
        refreshESState()
        doctorChecks = TelemetryDoctor.evaluate(await collectTelemetryFacts())
    }

    /// Applies one check's fix and re-runs the Doctor. With `waitForUser`, a
    /// fix that needs a System Settings switch polls every 2 s until the check
    /// passes or 5 minutes pass.
    func fixDoctorCheck(_ check: DoctorCheck, waitForUser: Bool) async {
        guard let fix = check.fix else { return }
        doctorFixing = check.id
        defer { doctorFixing = nil }
        applyDoctorFix(fix)
        await runDoctor()
        guard waitForUser, fix.needsUser else { return }
        let deadline = Date().addingTimeInterval(300)
        while !Task.isCancelled, Date() < deadline,
              doctorChecks.first(where: { $0.id == check.id })?.state != .pass {
            try? await Task.sleep(nanoseconds: 2_000_000_000)
            await runDoctor()
        }
    }

    /// Runs every offered fix in check order, each check at most once; later
    /// checks are re-evaluated after each fix.
    public func fixAllDoctorChecks() async {
        await runDoctor()
        var tried: Set<String> = []
        while let next = doctorChecks.first(where: { $0.state != .pass && $0.fix != nil && !tried.contains($0.id) }) {
            tried.insert(next.id)
            await fixDoctorCheck(next, waitForUser: true)
        }
    }

    private func applyDoctorFix(_ fix: DoctorFix) {
        lastError = nil
        switch fix {
        case .register:
            do { try installESCollector() } catch { report(error) }
        case .reregister:
            reregisterESService()
        case .openLoginItems:
            openESLoginItems()
        case .openFullDiskAccess:
            openESPermissions()
        case .setAsideSpool:
            do { _ = try TelemetryDoctor.setAsideSpool(spoolPath: Self.esSpoolPath, now: Date()) }
            catch { report(error) }
        case .removeLegacy:
            removeLegacyESHelper()
        case .openHarnessSetup:
            OnboardingWindowController.shared.show()
        }
        refreshESState()
    }

    /// `launchctl print` for the collector's job.
    nonisolated static func esLaunchdJob() -> LaunchdProbe {
        LaunchdProbe.parse(capture(["/bin/launchctl", "print", "system/\(esCollectorLabel)"]))
    }

    /// Runs a read-only tool and returns stdout and stderr together.
    private nonisolated static func capture(_ args: [String]) -> String {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: args[0])
        p.arguments = Array(args.dropFirst())
        let pipe = Pipe()
        p.standardOutput = pipe
        p.standardError = pipe
        do {
            try p.run()
        } catch {
            return ""
        }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        return String(decoding: data, as: UTF8.self)
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
        // Unregister the in-bundle ES collector daemon (best-effort: a
        // collector that was never registered has nothing to remove).
        try? uninstallESCollector()
        // Tear down any legacy LaunchAgent from an older install.
        let uid = getuid()
        Self.run(["/bin/launchctl", "bootout", "gui/\(uid)/\(Self.daemonLabel)"])
        if fm.fileExists(atPath: daemonPlistPath) {
            try fm.removeItem(atPath: daemonPlistPath)
        }
        if SMAppService.mainApp.status == .enabled {
            try? SMAppService.mainApp.unregister()
        }
        try Self.unregisterCursorHooks(at: Self.cursorHooksPath, command: Self.cursorHookCommand)
        for target in Self.hookTargets {
            for hook in ["secret_guard.py", "injection_scan.py", "activity_log.py"] {
                try? fm.removeItem(atPath: "\(target)/\(hook)")
            }
        }
        unregisterClaudeHooks()
        withdrawClaudeRouting()
        prefs.removeObject(forKey: Self.routeClaudeCodeKey)
        try? fm.removeItem(atPath: "\(home)/.local/bin/secure-agent")
    }

    // MARK: - Claude Code routing

    /// The operator's choice to route Claude Code through the proxy. The app
    /// re-applies it at launch and withdraws it at quit, so new Claude Code
    /// sessions never point at a proxy that is not running.
    static let routeClaudeCodeKey = "routeClaudeCode"

    /// Whether ~/.claude/settings.json carries Secure Agent's routing now.
    @Published public private(set) var claudeRoutingApplied = false

    /// Turns routing on (fetches the running daemon's environment and writes
    /// it) or off, and records the choice.
    public func setClaudeRouting(_ on: Bool) async {
        lastError = nil
        do {
            if on {
                let info = try await DaemonClient().fetchRouting()
                try ClaudeRouting.apply(at: Self.claudeSettingsPath, info: info)
            } else {
                try ClaudeRouting.remove(at: Self.claudeSettingsPath)
            }
            prefs.set(on, forKey: Self.routeClaudeCodeKey)
        } catch {
            report(error)
        }
        claudeRoutingApplied = ClaudeRouting.isApplied(at: Self.claudeSettingsPath)
    }

    /// At launch: when routing is on, write the running daemon's port and
    /// token again. The child daemon may still be starting, so this waits up
    /// to 10 s for it; until then Claude Code stays unrouted.
    public func reapplyClaudeRouting() async {
        defer { claudeRoutingApplied = ClaudeRouting.isApplied(at: Self.claudeSettingsPath) }
        guard prefs.bool(forKey: Self.routeClaudeCodeKey) else { return }
        for _ in 0..<20 {
            if let info = try? await DaemonClient().fetchRouting(), info.ready {
                do {
                    try ClaudeRouting.apply(at: Self.claudeSettingsPath, info: info)
                } catch {
                    report(error)
                }
                return
            }
            try? await Task.sleep(nanoseconds: 500_000_000)
        }
    }

    /// At quit: take routing back out of Claude Code's settings so new
    /// sessions reach the network directly while Secure Agent is not running.
    /// The choice is kept for the next launch.
    public func withdrawClaudeRouting() {
        try? ClaudeRouting.remove(at: Self.claudeSettingsPath)
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
        case notInstalledCopy

        public var errorDescription: String? {
            switch self {
            case .notBundled:
                return "This copy of Secure Agent is not running from its app bundle. Drag Secure Agent.app to /Applications and relaunch it."
            case .notInstalledCopy:
                return AppIdentity.wrongLocationMessage
            }
        }
    }
}

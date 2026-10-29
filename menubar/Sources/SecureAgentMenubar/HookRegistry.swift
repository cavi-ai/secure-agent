import CryptoKit
import Foundation

/// Harness hook installation and per-harness settings registration.
enum HookRegistry {
    static func hookDirectory(harness: String, home: String) -> String {
        harness == "openclaw" ? "\(home)/.openclaw/extensions/secure-agent" : "\(home)/.\(harness)/hooks"
    }

    /// Hook scripts shipped in a bundled hooks directory (tests excluded), and
    /// guard-rules.json, which secret_guard.py loads from its own directory.
    static func hookFileNames(in dir: String) throws -> [String] {
        try FileManager.default.contentsOfDirectory(atPath: dir)
            .filter { ($0.hasSuffix(".py") && !$0.hasPrefix("test_")) || $0 == "guard-rules.json" }
    }

    /// A selected path must never install into unrelated harnesses. Validate
    /// registration before replacing scripts, then use atomic file writes.
    static func installSelectedHooks(harness: String, bundledDir: String, home: String) throws {
        guard FirstUseSetupState.supportsHook(harness) else {
            throw NSError(domain: "SetupManager", code: 5, userInfo: [NSLocalizedDescriptionKey: "This harness has no supported guard hook."])
        }
        let fm = FileManager.default
        if harness == "openclaw" {
            let target = hookDirectory(harness: harness, home: home)
            if fm.fileExists(atPath: target) {
                guard let data = fm.contents(atPath: target + "/package.json"),
                      let package = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                      package["name"] as? String == "@cavi-ai/secure-agent-openclaw" else {
                    throw NSError(domain: "SetupManager", code: 5, userInfo: [NSLocalizedDescriptionKey: "The OpenClaw plugin directory belongs to another installation; it was left unchanged."])
                }
            }
            // Read every source before creating or replacing the plugin.
            var files: [String: Data] = [:]
            for file in try hookFileNames(in: bundledDir) {
                files[file] = try Data(contentsOf: URL(fileURLWithPath: bundledDir + "/" + file))
            }
            for file in ["package.json", "openclaw.plugin.json", "index.mjs"] {
                files[file] = try Data(contentsOf: URL(fileURLWithPath: bundledDir + "/openclaw/" + file))
            }
            try fm.createDirectory(atPath: target, withIntermediateDirectories: true)
            for (name, data) in files where fm.contents(atPath: target + "/" + name) != data {
                try data.write(to: URL(fileURLWithPath: target + "/" + name), options: .atomic)
            }
            return
        }
        let settings = "\(home)/.\(harness)/" + (harness == "claude" ? "settings.json" : "hooks.json")
        var original: Data?
        if harness == "codex" { (_, original) = try Codex.config(at: settings) }
        else if harness == "cursor" { (_, original) = try Cursor.config(at: settings) }
        else if let data = fm.contents(atPath: settings), !data.isEmpty {
            guard let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
                throw NSError(domain: "SetupManager", code: 3, userInfo: [NSLocalizedDescriptionKey: "Claude settings.json is not valid JSON; installed hooks were left unchanged."])
            }
            guard root["disableAllHooks"] == nil || root["disableAllHooks"] as? Bool == false else {
                throw NSError(domain: "SetupManager", code: 3, userInfo: [NSLocalizedDescriptionKey: "Claude has disabled hooks. Enable hooks in Claude settings before installing this path."])
            }
            let registration = root["hooks"] as? [String: Any]
            guard (root["hooks"] == nil || registration != nil),
                  ["PreToolUse", "PostToolUse"].allSatisfy({ event in
                      guard let groups = registration?[event] else { return true }
                      guard let groups = groups as? [[String: Any]] else { return false }
                      return groups.allSatisfy { $0["hooks"] == nil || $0["hooks"] is [[String: Any]] }
                  }) else {
                throw NSError(domain: "SetupManager", code: 3, userInfo: [NSLocalizedDescriptionKey: "Claude hook settings have an unsupported structure; installed hooks were left unchanged."])
            }
            original = data
        }
        if let original, !fm.fileExists(atPath: settings + ".bak-secure-agent") {
            try original.write(to: URL(fileURLWithPath: settings + ".bak-secure-agent"), options: .atomic)
        }
        let target = "\(home)/.\(harness)/hooks"
        let hooks = try hookFileNames(in: bundledDir)
        try fm.createDirectory(atPath: target, withIntermediateDirectories: true)
        for hook in hooks {
            try Data(contentsOf: URL(fileURLWithPath: "\(bundledDir)/\(hook)"))
                .write(to: URL(fileURLWithPath: "\(target)/\(hook)"), options: .atomic)
        }
        let command = selectedHookCommand(harness: harness, home: home)
        if harness == "codex" { try Codex.register(at: settings, command: command) }
        else if harness == "claude" { try Claude.register(at: settings, command: command) }
        else { try Cursor.register(at: settings, command: command) }
    }

    static func selectedHookCommand(harness: String, home: String) -> String {
        let script = harness == "codex" ? "harness_guard.py" : "secret_guard.py"
        let command = "python3 '" + "\(hookDirectory(harness: harness, home: home))/\(script)".replacingOccurrences(of: "'", with: "'\"'\"'") + "'"
        return command + (harness == "codex" ? " codex" : "")
    }

    static func selectedHooksInstalled(harness: String, home: String) -> Bool {
        guard FirstUseSetupState.supportsHook(harness) else { return false }
        let fm = FileManager.default
        let dir = hookDirectory(harness: harness, home: home)
        guard ["secret_guard.py", "activity_log.py", "injection_scan.py", "guard-rules.json"].allSatisfy({ fm.fileExists(atPath: "\(dir)/\($0)") }) else { return false }
        if harness == "openclaw" {
            return ["harness_guard.py", "package.json", "openclaw.plugin.json", "index.mjs"].allSatisfy { fm.fileExists(atPath: "\(dir)/\($0)") }
        }
        let command = selectedHookCommand(harness: harness, home: home)
        if harness == "codex" {
            return fm.fileExists(atPath: dir + "/harness_guard.py") && Codex.registered(at: "\(home)/.codex/hooks.json", command: command)
        }
        if harness == "cursor" { return Cursor.registered(at: "\(home)/.cursor/hooks.json", command: command) }
        let path = "\(home)/.claude/settings.json"
        guard let data = fm.contents(atPath: path),
              let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              (root["disableAllHooks"] == nil || root["disableAllHooks"] as? Bool == false),
              let hooks = root["hooks"] as? [String: Any] else { return false }
        // Existing installations used the unquoted canonical command. Accept
        // that spelling only when the path contains no shell metacharacters.
        let legacySafe = home.rangeOfCharacter(from: CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/_-." ).inverted) == nil
        let commands = legacySafe ? [command, "python3 \(dir)/secret_guard.py"] : [command]
        return ["PreToolUse", "PostToolUse"].allSatisfy { event in
            commands.contains { Claude.groupsContainGuard(hooks[event] as? [[String: Any]] ?? [], command: $0) }
        }
    }

    /// Codex user hooks use matcher groups; trust remains owned by Codex.
    enum Codex {
        static func config(at path: String) throws -> ([String: Any], Data?) {
            guard FileManager.default.fileExists(atPath: path) else { return ([:], nil) }
            let data = try Data(contentsOf: URL(fileURLWithPath: path))
            guard let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  root["hooks"] == nil || root["hooks"] is [String: Any] else { throw invalidConfig() }
            let hooks = root["hooks"] as? [String: Any] ?? [:]
            for event in ["PreToolUse", "PostToolUse"] {
                if let groups = hooks[event] {
                    guard let groups = groups as? [[String: Any]],
                          groups.allSatisfy({ $0["hooks"] is [[String: Any]] }) else { throw invalidConfig() }
                }
            }
            return (root, data)
        }

        private static func invalidConfig() -> NSError {
            NSError(domain: "SetupManager", code: 5, userInfo: [NSLocalizedDescriptionKey: "Codex hooks.json has an invalid or unsupported structure; it was left unchanged."])
        }

        private static func contains(_ groups: [[String: Any]], command: String) -> Bool {
            groups.contains { group in
                group["matcher"] == nil && (group["hooks"] as? [[String: Any]] ?? []).contains {
                    $0["command"] as? String == command && $0["type"] as? String == "command" &&
                    ($0["async"] == nil || $0["async"] as? Bool == false)
                }
            }
        }

        static func register(at path: String, command: String) throws {
            var (root, original) = try config(at: path)
            var hooks = root["hooks"] as? [String: Any] ?? [:]
            var changed = false
            for event in ["PreToolUse", "PostToolUse"] {
                var groups = hooks[event] as? [[String: Any]] ?? []
                if !contains(groups, command: command) {
                    groups.append(["hooks": [["type": "command", "command": command, "timeout": 60]]])
                    hooks[event] = groups
                    changed = true
                }
            }
            guard changed else { return }
            let fm = FileManager.default
            try fm.createDirectory(atPath: (path as NSString).deletingLastPathComponent, withIntermediateDirectories: true)
            if let original, !fm.fileExists(atPath: path + ".bak-secure-agent") {
                try original.write(to: URL(fileURLWithPath: path + ".bak-secure-agent"), options: .atomic)
            }
            root["hooks"] = hooks
            try JSONSerialization.data(withJSONObject: root, options: [.prettyPrinted, .sortedKeys])
                .write(to: URL(fileURLWithPath: path), options: .atomic)
        }

        static func registered(at path: String, command: String) -> Bool {
            guard let (root, _) = try? config(at: path), let hooks = root["hooks"] as? [String: Any] else { return false }
            return ["PreToolUse", "PostToolUse"].allSatisfy { contains(hooks[$0] as? [[String: Any]] ?? [], command: command) }
        }

        static func unregister(at path: String, command: String) throws {
            guard FileManager.default.fileExists(atPath: path) else { return }
            var (root, _) = try config(at: path)
            var hooks = root["hooks"] as? [String: Any] ?? [:]
            for event in ["PreToolUse", "PostToolUse"] {
                hooks[event] = (hooks[event] as? [[String: Any]] ?? []).compactMap { group -> [String: Any]? in
                    let kept = (group["hooks"] as? [[String: Any]] ?? []).filter { $0["command"] as? String != command }
                    guard !kept.isEmpty else { return nil }
                    var group = group
                    group["hooks"] = kept
                    return group
                }
            }
            root["hooks"] = hooks
            try JSONSerialization.data(withJSONObject: root, options: [.prettyPrinted, .sortedKeys])
                .write(to: URL(fileURLWithPath: path), options: .atomic)
        }
    }

    /// Overwrites each installed hook whose SHA-256 differs from the bundled
    /// copy and creates missing ones; identical files are left untouched.
    /// Returns the names written.
    @discardableResult
    static func refreshInstalledHooks(bundledDir: String, installedDir: String) throws -> [String] {
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

    private static func fileSHA256(_ path: String) -> String? {
        guard let data = FileManager.default.contents(atPath: path) else { return nil }
        return SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    /// Claude Code settings.json registration.
    enum Claude {
        /// Path-parameterized core of registerClaudeHooks (tests use temp files).
        static func register(at path: String, command: String) throws {
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
                if !fm.fileExists(atPath: path + ".bak-secure-agent") {
                    try data.write(to: URL(fileURLWithPath: path + ".bak-secure-agent"), options: .atomic)
                }
            }
            var hooks = root["hooks"] as? [String: Any] ?? [:]
            for eventName in ["PreToolUse", "PostToolUse"] {
                var groups = hooks[eventName] as? [[String: Any]] ?? []
                if !Self.groupsContainGuard(groups, command: command) {
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

        static func registered(at path: String) -> Bool {
            guard let data = FileManager.default.contents(atPath: path),
                  let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let hooks = root["hooks"] as? [String: Any] else { return false }
            return ["PreToolUse", "PostToolUse"].allSatisfy {
                Self.groupsContainGuard(hooks[$0] as? [[String: Any]] ?? [])
            }
        }

        static func unregister(at path: String) {
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

        fileprivate static func groupsContainGuard(_ groups: [[String: Any]], command: String? = nil) -> Bool {
            for group in groups {
                for h in group["hooks"] as? [[String: Any]] ?? [] {
                    if let command {
                        if h["command"] as? String == command && h["type"] as? String == "command" &&
                            (group["matcher"] == nil || group["matcher"] as? String == "*") { return true }
                        continue
                    }
                    if let cmd = h["command"] as? String, cmd.contains("/.claude/hooks/secret_guard.py") {
                        return true
                    }
                }
            }
            return false
        }
    }

    /// Cursor native tool hooks (hooks.json).
    enum Cursor {
        /// Cursor's native pre/post hooks cover all tool types. Keep user hooks
        /// and settings, reject unsupported schemas, and back up before mutation.
        static func config(at path: String) throws -> ([String: Any], Data?) {
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

        static func register(at path: String, command: String) throws {
            var (root, original) = try config(at: path)
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

        static func registered(at path: String, command: String) -> Bool {
            guard let (root, _) = try? config(at: path),
                  let hooks = root["hooks"] as? [String: Any] else { return false }
            return ["preToolUse", "postToolUse"].allSatisfy { event in
                (hooks[event] as? [[String: Any]] ?? []).contains {
                    ($0["command"] as? String) == command && $0["matcher"] == nil
                        && ($0["type"] == nil || ($0["type"] as? String) == "command")
                }
            }
        }

        static func unregister(at path: String, command: String) throws {
            guard FileManager.default.fileExists(atPath: path) else { return }
            var (root, _) = try config(at: path)
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
    }

    /// Runs the guard at hook with a harmless Read and checks it answers allow.
    /// environment replaces the inherited one when set (tests point the
    /// activity log at a temporary file).
    static func selfTestHook(at hook: String, environment: [String: String]? = nil) async -> String? {
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
}

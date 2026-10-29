import Foundation

extension HookRegistry {
    private static func registrationError(_ message: String) -> NSError {
        NSError(domain: "SetupManager", code: 5, userInfo: [NSLocalizedDescriptionKey: message])
    }

    private static func writeRegistration(_ data: Data, at path: String, original: Data?) throws {
        let fm = FileManager.default
        if data == original { return }
        try fm.createDirectory(atPath: (path as NSString).deletingLastPathComponent, withIntermediateDirectories: true)
        if let original, !fm.fileExists(atPath: path + ".bak-secure-agent") {
            try original.write(to: URL(fileURLWithPath: path + ".bak-secure-agent"), options: .atomic)
        }
        try data.write(to: URL(fileURLWithPath: path), options: .atomic)
    }

    static func installAdditionalHooks(harness: String, bundledDir: String, home: String, register: Bool = true) throws {
        let fm = FileManager.default
        let target = hookDirectory(harness: harness, home: home)
        let config = harness == "hermes" ? home + "/.hermes/config.yaml" : home + "/.gemini/config/hooks.json"
        let command = selectedHookCommand(harness: harness, home: home)
        if register && harness == "antigravity" { _ = try Antigravity.config(at: config, command: command) }
        if register && harness == "hermes" { _ = try Hermes.registration(at: config, enable: true) }
        if register && harness == "opencode" { _ = try OpenCode.config(at: OpenCode.configPath(home: home)) }
        let assets: [String]
        switch harness {
        case "hermes": assets = ["plugin.yaml", "__init__.py"]
        case "opencode": assets = ["package.json", "index.js"]
        default: assets = []
        }
        if !assets.isEmpty && fm.fileExists(atPath: target) {
            let markerFile = harness == "hermes" ? "plugin.yaml" : "index.js"
            let marker = "secure-agent-managed-plugin: " + (harness == "hermes" ? "hermes" : "opencode-v2")
            guard let data = fm.contents(atPath: target + "/" + markerFile),
                  String(decoding: data, as: UTF8.self).components(separatedBy: "\n").prefix(2).contains(where: { $0.contains(marker) }) else {
                throw registrationError("The \(harness) plugin directory belongs to another installation; it was left unchanged.")
            }
        }
        var files: [String: Data] = [:]
        for name in try hookFileNames(in: bundledDir) {
            files[name] = try Data(contentsOf: URL(fileURLWithPath: bundledDir + "/" + name))
        }
        for name in assets {
            files[name] = try Data(contentsOf: URL(fileURLWithPath: bundledDir + "/" + harness + "/" + name))
        }
        try fm.createDirectory(atPath: target, withIntermediateDirectories: true)
        for (name, data) in files where fm.contents(atPath: target + "/" + name) != data {
            try data.write(to: URL(fileURLWithPath: target + "/" + name), options: .atomic)
        }
        if register && harness == "hermes" { try Hermes.register(at: config) }
        if register && harness == "antigravity" { try Antigravity.register(at: config, command: command) }
        if register && harness == "opencode" { try OpenCode.register(home: home) }
    }

    static func uninstallAdditionalPlugin(harness: String, home: String) throws {
        let fm = FileManager.default
        let target = hookDirectory(harness: harness, home: home)
        let markerFile = harness == "hermes" ? "plugin.yaml" : "index.js"
        let marker = "secure-agent-managed-plugin: " + (harness == "hermes" ? "hermes" : "opencode-v2")
        guard let data = fm.contents(atPath: target + "/" + markerFile),
              String(decoding: data, as: UTF8.self).components(separatedBy: "\n").prefix(2).contains(where: { $0.contains(marker) }) else { return }
        if harness == "hermes" { try Hermes.unregister(at: home + "/.hermes/config.yaml") }
        if harness == "opencode" { try OpenCode.unregister(home: home) }
        let assets = harness == "hermes" ? ["plugin.yaml", "__init__.py"] : ["package.json", "index.js"]
        for name in assets + ["secret_guard.py", "activity_log.py", "injection_scan.py", "guard-rules.json", "harness_guard.py"] {
            if fm.fileExists(atPath: target + "/" + name) { try fm.removeItem(atPath: target + "/" + name) }
        }
    }

    enum OpenCode {
        static func configPath(home: String) -> String {
            let base = home + "/.config/opencode/opencode.json"
            return FileManager.default.fileExists(atPath: base + "c") ? base + "c" : base
        }

        static func config(at path: String) throws -> ([String: Any], Data?) {
            guard FileManager.default.fileExists(atPath: path) else { return ([:], nil) }
            let original = try Data(contentsOf: URL(fileURLWithPath: path))
            guard let root = try? JSONSerialization.jsonObject(with: original, options: [.json5Allowed]) as? [String: Any],
                  root["plugins"] == nil || root["plugins"] is [Any] else {
                throw registrationError("OpenCode configuration is invalid or has unsupported plugin entries; it was left unchanged.")
            }
            let entries = root["plugins"] as? [Any] ?? []
            guard entries.allSatisfy({ $0 is String || ($0 as? [String: Any])?["package"] is String }) else {
                throw registrationError("OpenCode configuration has unsupported plugin entries; it was left unchanged.")
            }
            return (root, original)
        }

        static func register(home: String) throws {
            let path = configPath(home: home)
            var (root, original) = try config(at: path)
            var entries = root["plugins"] as? [Any] ?? []
            let target = hookDirectory(harness: "opencode", home: home)
            guard !entries.contains(where: { ($0 as? String ?? ($0 as? [String: Any])?["package"] as? String) == target }) else { return }
            entries.append(target)
            root["plugins"] = entries
            try writeRegistration(JSONSerialization.data(withJSONObject: root, options: [.prettyPrinted, .sortedKeys]), at: path, original: original)
        }

        static func registered(home: String) -> Bool {
            let target = hookDirectory(harness: "opencode", home: home)
            return [home + "/.config/opencode/opencode.json", home + "/.config/opencode/opencode.jsonc"].contains { path in
                guard let (root, _) = try? config(at: path) else { return false }
                return (root["plugins"] as? [Any] ?? []).contains { ($0 as? String ?? ($0 as? [String: Any])?["package"] as? String) == target }
            }
        }

        static func unregister(home: String) throws {
            let target = hookDirectory(harness: "opencode", home: home)
            for path in [home + "/.config/opencode/opencode.json", home + "/.config/opencode/opencode.jsonc"] where FileManager.default.fileExists(atPath: path) {
                var (root, original) = try config(at: path)
                let entries = root["plugins"] as? [Any] ?? []
                let kept = entries.filter { ($0 as? String ?? ($0 as? [String: Any])?["package"] as? String) != target }
                guard kept.count != entries.count else { continue }
                root["plugins"] = kept
                try writeRegistration(JSONSerialization.data(withJSONObject: root, options: [.prettyPrinted, .sortedKeys]), at: path, original: original)
            }
        }
    }

    enum Hermes {
        static func registration(at path: String, enable: Bool) throws -> (Data, Data?) {
            let original = FileManager.default.contents(atPath: path)
            guard original == nil || String(data: original!, encoding: .utf8) != nil else {
                throw registrationError("Hermes config.yaml is not UTF-8; it was left unchanged.")
            }
            var document = ConfigDocument(original.map { String(decoding: $0, as: UTF8.self) } ?? "")
            var enabled = try document.list("enabled", in: "plugins") ?? []
            var disabled = try document.list("disabled", in: "plugins") ?? []
            if enable {
                if !enabled.contains("secure-agent") { enabled.append("secure-agent") }
                disabled.removeAll { $0 == "secure-agent" }
            } else {
                enabled.removeAll { $0 == "secure-agent" }
                if !disabled.contains("secure-agent") { disabled.append("secure-agent") }
            }
            document = try document.settingList("enabled", to: enabled, in: "plugins")
            if try document.list("disabled", in: "plugins") != nil || !disabled.isEmpty {
                document = try document.settingList("disabled", to: disabled, in: "plugins")
            }
            return (Data(document.text.utf8), original)
        }

        static func register(at path: String) throws {
            let (data, original) = try registration(at: path, enable: true)
            try writeRegistration(data, at: path, original: original)
        }

        static func registered(at path: String) -> Bool {
            guard let text = try? String(contentsOfFile: path, encoding: .utf8) else { return false }
            let document = ConfigDocument(text)
            do {
                let enabled = try document.list("enabled", in: "plugins") ?? []
                let disabled = try document.list("disabled", in: "plugins") ?? []
                return enabled.contains("secure-agent") && !disabled.contains("secure-agent")
            } catch { return false }
        }

        static func unregister(at path: String) throws {
            let (data, original) = try registration(at: path, enable: false)
            try writeRegistration(data, at: path, original: original)
        }
    }

    enum Antigravity {
        static func config(at path: String, command: String, requireEnabled: Bool = true) throws -> ([String: Any], Data?) {
            guard FileManager.default.fileExists(atPath: path) else { return ([:], nil) }
            let data = try Data(contentsOf: URL(fileURLWithPath: path))
            guard let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
                throw registrationError("Antigravity hooks.json is invalid; it was left unchanged.")
            }
            if let value = root["secure-agent"] {
                guard let hook = value as? [String: Any], !requireEnabled || hook["enabled"] == nil || hook["enabled"] as? Bool == true,
                      ["PreToolUse", "PostToolUse"].allSatisfy({ event in
                          guard let groups = hook[event] else { return true }
                          guard let groups = groups as? [[String: Any]] else { return false }
                          return groups.allSatisfy { $0["hooks"] is [[String: Any]] }
                      }),
                      ["PreToolUse", "PostToolUse"].contains(where: { event in
                          (hook[event] as? [[String: Any]] ?? []).contains { group in
                              (group["hooks"] as? [[String: Any]] ?? []).contains { $0["command"] as? String == command + " " + event }
                          }
                      }) else {
                    throw registrationError("The Antigravity secure-agent hook is disabled or belongs to another hook. Review it in Antigravity; it was left unchanged.")
                }
            }
            return (root, data)
        }

        static func register(at path: String, command: String) throws {
            var (root, original) = try config(at: path, command: command)
            var hook = root["secure-agent"] as? [String: Any] ?? [:]
            for event in ["PreToolUse", "PostToolUse"] {
                var groups = hook[event] as? [[String: Any]] ?? []
                if !groups.contains(where: { ($0["matcher"] == nil || $0["matcher"] as? String == "*") &&
                    ($0["hooks"] as? [[String: Any]] ?? []).contains { $0["command"] as? String == command + " " + event } }) {
                    groups.append(["matcher": "*", "hooks": [["type": "command", "command": command + " " + event, "timeout": 60]]])
                }
                hook[event] = groups
            }
            root["secure-agent"] = hook
            let data = try JSONSerialization.data(withJSONObject: root, options: [.prettyPrinted, .sortedKeys])
            try writeRegistration(data, at: path, original: original)
        }

        static func registered(at path: String, command: String) -> Bool {
            guard let (root, _) = try? config(at: path, command: command), let hook = root["secure-agent"] as? [String: Any] else { return false }
            return ["PreToolUse", "PostToolUse"].allSatisfy { event in
                (hook[event] as? [[String: Any]] ?? []).contains { group in
                    (group["matcher"] == nil || group["matcher"] as? String == "*") &&
                    (group["hooks"] as? [[String: Any]] ?? []).contains { $0["command"] as? String == command + " " + event }
                }
            }
        }

        static func unregister(at path: String, command: String) throws {
            guard FileManager.default.fileExists(atPath: path) else { return }
            var (root, original) = try config(at: path, command: command, requireEnabled: false)
            guard var hook = root["secure-agent"] as? [String: Any] else { return }
            for event in ["PreToolUse", "PostToolUse"] {
                hook[event] = (hook[event] as? [[String: Any]] ?? []).compactMap { group -> [String: Any]? in
                    let kept = (group["hooks"] as? [[String: Any]] ?? []).filter { $0["command"] as? String != command + " " + event }
                    guard !kept.isEmpty else { return nil }
                    var group = group; group["hooks"] = kept; return group
                }
            }
            let knownKeys: Set<String> = ["enabled", "PreToolUse", "PostToolUse"]
            let empty = ["PreToolUse", "PostToolUse"].allSatisfy { (hook[$0] as? [[String: Any]] ?? []).isEmpty }
            if empty && Set(hook.keys).isSubset(of: knownKeys) { root.removeValue(forKey: "secure-agent") }
            else { root["secure-agent"] = hook }
            try writeRegistration(JSONSerialization.data(withJSONObject: root, options: [.prettyPrinted, .sortedKeys]), at: path, original: original)
        }
    }
}

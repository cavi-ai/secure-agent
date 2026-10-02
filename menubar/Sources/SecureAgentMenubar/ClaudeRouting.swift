import Foundation

/// The daemon's answer to GET /routing/claude.
public struct RoutingInfo: Codable, Equatable, Sendable {
    public let ready: Bool
    public let reason: String?
    public let env: [String: String]?
    public let bashEnvPath: String?

    enum CodingKeys: String, CodingKey {
        case ready, reason, env
        case bashEnvPath = "bash_env_path"
    }
}

/// Routes Claude Code through Secure Agent's proxy from its user settings
/// (~/.claude/settings.json): the daemon's environment for Claude Code's own
/// process, and a SessionStart hook that appends the tunnel-mode snippet to
/// each session's Bash environment. Merge, never clobber: a value the user set
/// is never overwritten, and removal takes back only the keys Secure Agent
/// added.
enum ClaudeRouting {
    /// Lists the env keys Secure Agent added, so removal takes back only those.
    static let markerKey = "SECURE_AGENT_ROUTED_KEYS"
    /// Every routing hook command reads the snippet at this path suffix.
    static let snippetSuffix = "/secure-agent/agent-env.sh"

    enum RoutingError: LocalizedError, Equatable {
        case invalidJSON
        case notReady(String)
        case conflict(String)

        var errorDescription: String? {
            switch self {
            case .invalidJSON:
                return "~/.claude/settings.json is not valid JSON — not touching it; fix or back it up first"
            case .notReady(let reason):
                return "Claude Code routing is not available: \(reason)"
            case .conflict(let key):
                return "~/.claude/settings.json already sets \(key); Secure Agent will not replace it"
            }
        }
    }

    /// The SessionStart hook command: append the snippet to the session's Bash
    /// environment file when Claude Code provides one.
    static func hookCommand(bashEnvPath: String) -> String {
        let quoted = "'" + bashEnvPath.replacingOccurrences(of: "'", with: "'\\''") + "'"
        return "[ -n \"$CLAUDE_ENV_FILE\" ] && cat \(quoted) >> \"$CLAUDE_ENV_FILE\" 2>/dev/null; true"
    }

    /// Writes info's environment and the SessionStart hook into the settings
    /// file at path. Re-applying replaces Secure Agent's own values (a new
    /// port or token); a key the user set is a conflict.
    static func apply(at path: String, info: RoutingInfo) throws {
        guard info.ready, let env = info.env, !env.isEmpty, let bashEnvPath = info.bashEnvPath else {
            throw RoutingError.notReady(info.reason ?? "the daemon did not return a routing environment")
        }
        var root = try load(path) ?? [:]
        var settingsEnv = root["env"] as? [String: Any] ?? [:]
        let owned = ownedKeys(settingsEnv)
        for key in env.keys.sorted() where !owned.contains(key) {
            if let existing = settingsEnv[key], (existing as? String) != env[key] {
                throw RoutingError.conflict(key)
            }
        }
        for (key, value) in env {
            settingsEnv[key] = value
        }
        settingsEnv[markerKey] = env.keys.sorted().joined(separator: ",")
        root["env"] = settingsEnv

        var hooks = root["hooks"] as? [String: Any] ?? [:]
        var groups = withoutRoutingHook(hooks["SessionStart"] as? [[String: Any]] ?? []).groups
        groups.append(["hooks": [["type": "command", "command": hookCommand(bashEnvPath: bashEnvPath)]]])
        hooks["SessionStart"] = groups
        root["hooks"] = hooks
        try write(root, to: path)
    }

    /// Takes back the keys and hook Secure Agent added; everything else in the
    /// file stays. A missing file, or one with nothing of ours, is unchanged.
    static func remove(at path: String) throws {
        guard var root = try load(path) else { return }
        var changed = false
        if var settingsEnv = root["env"] as? [String: Any], settingsEnv[markerKey] != nil {
            for key in ownedKeys(settingsEnv) {
                settingsEnv.removeValue(forKey: key)
            }
            settingsEnv.removeValue(forKey: markerKey)
            root["env"] = settingsEnv.isEmpty ? nil : settingsEnv
            changed = true
        }
        if var hooks = root["hooks"] as? [String: Any], let groups = hooks["SessionStart"] as? [[String: Any]] {
            let (kept, removed) = withoutRoutingHook(groups)
            if removed > 0 {
                hooks["SessionStart"] = kept.isEmpty ? nil : kept
                root["hooks"] = hooks
                changed = true
            }
        }
        if changed {
            try write(root, to: path)
        }
    }

    /// Whether the settings file at path carries Secure Agent's routing.
    static func isApplied(at path: String) -> Bool {
        guard let root = try? load(path), let settingsEnv = root["env"] as? [String: Any] else { return false }
        return settingsEnv[markerKey] != nil
    }

    private static func ownedKeys(_ settingsEnv: [String: Any]) -> Set<String> {
        let listed = settingsEnv[markerKey] as? String ?? ""
        return Set(listed.split(separator: ",").map(String.init))
    }

    /// groups without Secure Agent's routing hook, and how many hooks that
    /// took out. A group left with no hooks is dropped.
    private static func withoutRoutingHook(_ groups: [[String: Any]]) -> (groups: [[String: Any]], removed: Int) {
        var removed = 0
        let kept: [[String: Any]] = groups.compactMap { group in
            let all = group["hooks"] as? [[String: Any]] ?? []
            let others = all.filter { hook in
                !((hook["command"] as? String)?.contains(snippetSuffix) ?? false)
            }
            removed += all.count - others.count
            if others.isEmpty && !all.isEmpty { return nil }
            var g = group
            g["hooks"] = others
            return g
        }
        return (kept, removed)
    }

    /// The parsed settings file; nil when it does not exist. Backs it up
    /// before any write, as hook registration does.
    private static func load(_ path: String) throws -> [String: Any]? {
        guard let data = FileManager.default.contents(atPath: path) else { return nil }
        if data.isEmpty { return [:] }
        guard let root = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else {
            throw RoutingError.invalidJSON
        }
        try? data.write(to: URL(fileURLWithPath: path + ".bak-secure-agent"), options: .atomic)
        return root
    }

    private static func write(_ root: [String: Any], to path: String) throws {
        try FileManager.default.createDirectory(atPath: (path as NSString).deletingLastPathComponent,
                                                withIntermediateDirectories: true)
        let data = try JSONSerialization.data(withJSONObject: root, options: [.prettyPrinted, .sortedKeys])
        try data.write(to: URL(fileURLWithPath: path), options: .atomic)
    }
}

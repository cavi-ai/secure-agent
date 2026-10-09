import Foundation

/// Edits only advisor-owned scalar fields; unsupported YAML stays untouched.
struct AdvisorPreferences: Equatable, Sendable {
    var timeoutMS = 60000
    var classifierEndpoint = ""
    var classifierModel = "kev-latest"
    var debug = false

    enum PreferenceError: LocalizedError {
        case unsupported, endpoint, timeout
        var errorDescription: String? {
            switch self {
            case .unsupported: "Advisor settings could not be read safely. Use one advisor block with scalar settings in config.yaml. The file was left unchanged."
            case .endpoint: "Use an HTTP or HTTPS loopback endpoint (127.0.0.1, localhost or ::1), without credentials, a query or a fragment."
            case .timeout: "Enter a positive whole number of seconds."
            }
        }
    }

    static func isLoopbackEndpoint(_ text: String) -> Bool {
        guard let url = URLComponents(string: text), ["http", "https"].contains(url.scheme?.lowercased() ?? ""),
              let host = url.host?.lowercased(), ["127.0.0.1", "localhost", "::1", "[::1]"].contains(host),
              url.user == nil, url.password == nil, url.query == nil, url.fragment == nil else { return false }
        return true
    }

    static func read(_ yaml: String) throws -> Self {
        let lines = yaml.components(separatedBy: "\n")
        guard let block = try blockRange(lines) else { return Self() }
        var p = Self()
        if let value = try value(lines, block, "timeout_ms") {
            guard let n = Int(value), n > 0 else { throw PreferenceError.timeout }
            p.timeoutMS = n
        }
        if let value = try value(lines, block, "classifier_endpoint") { p.classifierEndpoint = value }
        if let value = try value(lines, block, "classifier_model") { p.classifierModel = value }
        if let value = try value(lines, block, "debug") {
            guard value == "true" || value == "false" else { throw PreferenceError.unsupported }
            p.debug = value == "true"
        }
        return p
    }

    func updating(_ yaml: String) throws -> String {
        _ = try Self.read(yaml)
        guard timeoutMS > 0 else { throw PreferenceError.timeout }
        guard classifierEndpoint.isEmpty || Self.isLoopbackEndpoint(classifierEndpoint) else { throw PreferenceError.endpoint }
        return try Self.patch(yaml, fields: [
            ("timeout_ms", String(timeoutMS)), ("classifier_endpoint", Self.quoted(classifierEndpoint)),
            ("classifier_model", Self.quoted(classifierModel)), ("debug", debug ? "true" : "false")
        ])
    }

    static func settingModel(_ yaml: String, managed: Bool, endpoint: String?, model: String) throws -> String {
        _ = try read(yaml)
        if !managed && !isLoopbackEndpoint(endpoint ?? SetupManager.advisorEndpoint) { throw PreferenceError.endpoint }
        var fields: [(String, String?)] = [("enabled", "true"),
            ("managed", managed ? "true" : nil), ("managed_model", managed ? quoted(model) : nil),
            ("endpoint", managed ? nil : quoted(endpoint ?? SetupManager.advisorEndpoint)),
            ("model", managed ? nil : quoted(model))]
        let lines = yaml.components(separatedBy: "\n")
        if let block = try blockRange(lines) {
            if try value(lines, block, "timeout_ms") == nil { fields.append(("timeout_ms", "60000")) }
        } else { fields.append(("timeout_ms", "60000")) }
        return try patch(yaml, fields: fields)
    }

    static func settingEnabled(_ yaml: String, enabled: Bool) throws -> String {
        _ = try read(yaml)
        var fields: [(String, String?)] = [("enabled", enabled ? "true" : "false")]
        if try blockRange(yaml.components(separatedBy: "\n")) == nil {
            fields += [("endpoint", quoted(SetupManager.advisorEndpoint)), ("model", quoted("")), ("timeout_ms", "60000")]
        }
        return try patch(yaml, fields: fields)
    }

    // JSON strings are valid YAML scalars and escape quotes/control characters.
    private static func quoted(_ text: String) -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = .withoutEscapingSlashes
        return String(decoding: try! encoder.encode(text), as: UTF8.self)
    }

    private static func blockRange(_ lines: [String]) throws -> Range<Int>? {
        guard !lines.contains(where: { $0.hasPrefix("{") || $0.hasPrefix("---") || $0.hasPrefix("...") }) else {
            throw PreferenceError.unsupported
        }
        let starts = lines.indices.filter { lines[$0].range(of: #"^[\"']?advisor[\"']?\s*:"#, options: .regularExpression) != nil }
        guard starts.count <= 1 else { throw PreferenceError.unsupported }
        guard let start = starts.first else { return nil }
        guard lines[start].hasPrefix("advisor:") else { throw PreferenceError.unsupported }
        let suffix = lines[start].dropFirst("advisor:".count).trimmingCharacters(in: .whitespaces)
        guard suffix.isEmpty || suffix.hasPrefix("#") else { throw PreferenceError.unsupported }
        let end = lines.indices.dropFirst(start + 1).first {
            !lines[$0].hasPrefix(" ") && !lines[$0].trimmingCharacters(in: .whitespaces).isEmpty && !lines[$0].hasPrefix("#")
        } ?? lines.count
        guard !lines[(start + 1)..<end].contains(where: { $0.hasPrefix("\t") }) else { throw PreferenceError.unsupported }
        return (start + 1)..<end
    }

    private static func field(_ lines: [String], _ block: Range<Int>, _ key: String) throws -> Int? {
        let meaningful = block.filter {
            let s = lines[$0].trimmingCharacters(in: .whitespaces)
            return !s.isEmpty && !s.hasPrefix("#")
        }
        let indent = meaningful.map { lines[$0].prefix { $0 == " " }.count }.min() ?? 2
        let matches = meaningful.filter {
            lines[$0].prefix { $0 == " " }.count == indent && lines[$0].trimmingCharacters(in: .whitespaces).hasPrefix(key + ":")
        }
        guard matches.count <= 1 else { throw PreferenceError.unsupported }
        guard let i = matches.first else { return nil }
        if let next = meaningful.first(where: { $0 > i }), lines[next].prefix(while: { $0 == " " }).count > indent {
            throw PreferenceError.unsupported
        }
        return i
    }

    private static func value(_ lines: [String], _ block: Range<Int>, _ key: String) throws -> String? {
        guard let i = try field(lines, block, key) else { return nil }
        let raw = lines[i].trimmingCharacters(in: .whitespaces).dropFirst(key.count + 1).trimmingCharacters(in: .whitespaces)
        if raw.isEmpty || raw.hasPrefix("#") { return "" }
        if raw.hasPrefix("\"") {
            // Find the closing unescaped quote; preserve # inside quoted strings.
            var escaped = false
            for j in raw.indices.dropFirst() {
                let c = raw[j]
                if c == "\"" && !escaped {
                    let tail = raw[raw.index(after: j)...].trimmingCharacters(in: .whitespaces)
                    guard tail.isEmpty || tail.hasPrefix("#"),
                          let s = try? JSONDecoder().decode(String.self, from: Data(raw[...j].utf8)) else { throw PreferenceError.unsupported }
                    return s
                }
                escaped = c == "\\" && !escaped
            }
            throw PreferenceError.unsupported
        }
        if raw.hasPrefix("'") {
            let pattern = #"^'((?:[^']|'')*)'\s*(?:#.*)?$"#
            let regex = try NSRegularExpression(pattern: pattern)
            guard let match = regex.firstMatch(in: raw, range: NSRange(raw.startIndex..., in: raw)),
                  let range = Range(match.range(at: 1), in: raw) else { throw PreferenceError.unsupported }
            return String(raw[range]).replacingOccurrences(of: "''", with: "'")
        }
        let s = String(raw.split(separator: "#", maxSplits: 1, omittingEmptySubsequences: false)[0]).trimmingCharacters(in: .whitespaces)
        guard !s.isEmpty, !["[", "{", "|", ">", "*", "&", "!"].contains(where: { s.hasPrefix($0) }) else { throw PreferenceError.unsupported }
        return s
    }

    private static func patch(_ yaml: String, fields: [(String, String?)]) throws -> String {
        var lines = yaml.components(separatedBy: "\n")
        if try blockRange(lines) == nil {
            if lines.last == "" { lines.removeLast() }
            lines += ["advisor:", ""]
        }
        for (key, value) in fields {
            let block = try blockRange(lines)!
            if let i = try field(lines, block, key) {
                let indent = String(lines[i].prefix { $0 == " " })
                if let value { lines[i] = indent + key + ": " + value } else { lines.remove(at: i) }
            } else if let value {
                let indent = block.filter { !lines[$0].trimmingCharacters(in: .whitespaces).isEmpty && !lines[$0].trimmingCharacters(in: .whitespaces).hasPrefix("#") }
                    .map { lines[$0].prefix { $0 == " " }.count }.min() ?? 2
                lines.insert(String(repeating: " ", count: indent) + key + ": " + value, at: block.lowerBound)
            }
        }
        return lines.joined(separator: "\n")
    }
}

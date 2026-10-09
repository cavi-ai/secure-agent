import Foundation

/// A narrow editor for the two automatic-review fields in user-owned YAML.
/// Unsupported YAML forms fail without rewriting the file.
struct AutoReviewPolicy: Equatable, Sendable {
    var minimumSeverity = 2
    var excludedRules: [String] = []

    private static let severityKey = "auto_review_min_severity"
    private static let rulesKey = "auto_review_excluded_rules"

    private enum PolicyError: LocalizedError {
        case unsupported
        var errorDescription: String? {
            "Automatic review settings could not be read safely. Use a system_agent block with a severity from 1 to 3 and a list of excluded rule IDs in config.yaml. The file was left unchanged."
        }
    }

    static func read(_ yaml: String) throws -> Self {
        let lines = yaml.components(separatedBy: "\n")
        guard let block = try blockRange(lines) else { return Self() }
        var policy = Self()
        if let field = try fieldRange(lines, block: block, key: severityKey) {
            guard lines[(field.lowerBound + 1)..<field.upperBound].allSatisfy({ uncomment($0).isEmpty }),
                  let value = Int(scalar(lines[field.lowerBound], key: severityKey)),
                  (0...3).contains(value) else { throw PolicyError.unsupported }
            policy.minimumSeverity = value == 0 ? 2 : value
        }
        if let field = try fieldRange(lines, block: block, key: rulesKey) {
            let value = scalar(lines[field.lowerBound], key: rulesKey)
            if value.hasPrefix("["), value.hasSuffix("]"),
               lines[(field.lowerBound + 1)..<field.upperBound].allSatisfy({ uncomment($0).isEmpty }) {
                let body = value.dropFirst().dropLast().trimmingCharacters(in: .whitespaces)
                policy.excludedRules = body.isEmpty ? [] : try body.components(separatedBy: ",").map(ruleID)
            } else if value.isEmpty {
                policy.excludedRules = try lines[(field.lowerBound + 1)..<field.upperBound].compactMap { line in
                    let entry = uncomment(line)
                    if entry.isEmpty { return nil }
                    guard entry.hasPrefix("-") else { throw PolicyError.unsupported }
                    return try ruleID(String(entry.dropFirst()))
                }
            } else { throw PolicyError.unsupported }
        }
        return policy
    }

    func updating(_ yaml: String) throws -> String {
        _ = try Self.read(yaml) // Never overwrite a policy we could not read.
        guard (1...3).contains(minimumSeverity) else { throw PolicyError.unsupported }
        for rule in excludedRules { _ = try Self.ruleID(rule) }
        var lines = yaml.components(separatedBy: "\n")
        if try Self.blockRange(lines) == nil {
            if lines.last == "" { lines.removeLast() }
            lines.append("system_agent:")
            lines.append("")
        }
        try Self.replace(&lines, key: Self.severityKey, value: String(minimumSeverity))
        // JSON flow sequences are valid YAML; simple validated IDs need no
        // escaping and remain readable to operators editing the file.
        let list = "[" + excludedRules.map { "\"" + $0 + "\"" }.joined(separator: ", ") + "]"
        try Self.replace(&lines, key: Self.rulesKey, value: list)
        return lines.joined(separator: "\n")
    }

    private static func blockRange(_ lines: [String]) throws -> Range<Int>? {
        let starts = lines.indices.filter { lines[$0].hasPrefix("system_agent:") }
        guard starts.count <= 1 else { throw PolicyError.unsupported }
        guard let start = starts.first else { return nil }
        guard uncomment(String(lines[start].dropFirst("system_agent:".count))).isEmpty else {
            throw PolicyError.unsupported
        }
        let end = lines.indices.dropFirst(start + 1).first {
            !lines[$0].hasPrefix(" ") && !uncomment(lines[$0]).isEmpty
        } ?? lines.count
        return (start + 1)..<end
    }

    private static func fieldRange(_ lines: [String], block: Range<Int>, key: String) throws -> Range<Int>? {
        let meaningful = block.filter { !uncomment(lines[$0]).isEmpty }
        let indent = meaningful.map { indentation(lines[$0]) }.min() ?? 2
        let matches = meaningful.filter {
            indentation(lines[$0]) == indent && uncomment(lines[$0]).hasPrefix(key + ":")
        }
        guard matches.count <= 1 else { throw PolicyError.unsupported }
        guard let start = matches.first else { return nil }
        var end = start + 1
        var cursor = end
        while cursor < block.upperBound {
            let content = uncomment(lines[cursor])
            if content.isEmpty { cursor += 1; continue }
            // YAML permits sequence entries at the field's own indentation.
            guard indentation(lines[cursor]) > indent ||
                    (indentation(lines[cursor]) == indent && content.hasPrefix("-")) else { break }
            end = cursor + 1
            cursor += 1
        }
        return start..<end
    }

    private static func replace(_ lines: inout [String], key: String, value: String) throws {
        guard let block = try blockRange(lines) else { throw PolicyError.unsupported }
        if let field = try fieldRange(lines, block: block, key: key) {
            let indent = String(repeating: " ", count: indentation(lines[field.lowerBound]))
            lines.replaceSubrange(field, with: [indent + key + ": " + value])
        } else {
            let indent = block.filter { !uncomment(lines[$0]).isEmpty }
                .map { indentation(lines[$0]) }.min() ?? 2
            lines.insert(String(repeating: " ", count: indent) + key + ": " + value, at: block.lowerBound)
        }
    }

    private static func scalar(_ line: String, key: String) -> String {
        uncomment(String(line.trimmingCharacters(in: .whitespaces).dropFirst(key.count + 1)))
    }

    private static func indentation(_ line: String) -> Int { line.prefix { $0 == " " }.count }
    private static func uncomment(_ text: String) -> String {
        String(text.split(separator: "#", maxSplits: 1, omittingEmptySubsequences: false)[0])
            .trimmingCharacters(in: .whitespaces)
    }

    private static func unquote(_ text: String) -> String {
        let value = text.trimmingCharacters(in: .whitespaces)
        if value.count >= 2 && ((value.first == "\"" && value.last == "\"") || (value.first == "'" && value.last == "'")) {
            return String(value.dropFirst().dropLast())
        }
        return value
    }

    private static func ruleID(_ text: String) throws -> String {
        let value = unquote(text)
        guard value.range(of: "^[a-z0-9][a-z0-9-]*$", options: .regularExpression) != nil else {
            throw PolicyError.unsupported
        }
        return value
    }
}

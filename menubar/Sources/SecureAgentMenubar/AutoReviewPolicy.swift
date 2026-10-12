import Foundation

/// A narrow editor for the two automatic-review fields in user-owned YAML.
/// Unsupported YAML forms fail without rewriting the file.
struct AutoReviewPolicy: Equatable, Sendable {
    var minimumSeverity = 2
    var excludedRules: [String] = []

    private static let block = "system_agent"
    private static let severityKey = "auto_review_min_severity"
    private static let rulesKey = "auto_review_excluded_rules"

    private enum PolicyError: LocalizedError {
        case unsupported
        var errorDescription: String? {
            "Automatic review settings could not be read safely. Use a system_agent block with a severity from 1 to 3 and a list of excluded rule IDs in config.yaml. The file was left unchanged."
        }
    }

    static func read(_ yaml: String) throws -> Self {
        let document = ConfigDocument(yaml)
        var policy = Self()
        if let severity = try document.scalar(severityKey, in: block) {
            guard !severity.isQuoted, let value = Int(severity.text), (0...3).contains(value) else { throw PolicyError.unsupported }
            policy.minimumSeverity = value == 0 ? 2 : value
        }
        if let rules = try document.list(rulesKey, in: block) { policy.excludedRules = try rules.map(ruleID) }
        return policy
    }

    func updating(_ yaml: String) throws -> String {
        _ = try Self.read(yaml) // Never overwrite a policy we could not read.
        guard (1...3).contains(minimumSeverity) else { throw PolicyError.unsupported }
        for rule in excludedRules { _ = try Self.ruleID(rule) }
        return try ConfigDocument(yaml)
            .setting(Self.severityKey, raw: String(minimumSeverity), in: Self.block)
            .settingList(Self.rulesKey, to: excludedRules, in: Self.block).text
    }

    private static func ruleID(_ text: String) throws -> String {
        guard text.range(of: "^[a-z0-9][a-z0-9-]*$", options: .regularExpression) != nil else {
            throw PolicyError.unsupported
        }
        return text
    }
}

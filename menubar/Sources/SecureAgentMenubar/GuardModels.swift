import Foundation

public struct GuardPending: Codable, Identifiable, Sendable {
    public let id: String
    public let agent: String
    public let tool: String
    public let path: String
    public let ruleID: String
    public let ts: String
    public let scopeText: String?
    /// The local advisor's recommendation, when one has landed. Advisory only:
    /// the human still decides; this is shown inline to inform the choice.
    public let advisor: GuardAdvice?
    enum CodingKeys: String, CodingKey { case id, agent, tool, path, ts, advisor; case ruleID = "rule_id"; case scopeText = "scope_text" }
}

/// The advisor's read on a blocked guard prompt (decoded from the shared
/// AdvisorVerdict wire shape). assessment: benign|suspicious|malicious.
public struct GuardAdvice: Codable, Sendable {
    public let assessment: String?
    public let confidence: Double?
    public let rationale: String
    enum CodingKeys: String, CodingKey { case assessment, confidence, rationale }

    /// A one-word recommendation derived from the assessment, for the chip.
    public var recommendation: String {
        switch assessment {
        case "benign": return "allow"
        case "malicious": return "deny"
        default: return "look"
        }
    }
}

public struct GuardResolveRequest: Codable, Sendable {
    public let id: String
    public let verdict: String   // allow | deny
    public let scope: String     // once | always
}

public struct GuardRuleModel: Codable, Identifiable, Sendable {
    public var id: String { "\(agent)/\(ruleID)" }
    public let agent: String
    public let ruleID: String
    public let decision: String
    public let source: String
    public let createdAt: String
    enum CodingKeys: String, CodingKey { case agent, decision, source; case ruleID = "rule_id"; case createdAt = "created_at" }
}

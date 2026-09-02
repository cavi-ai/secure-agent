import Foundation

public struct GuardPending: Codable, Identifiable, Sendable {
    public let id: String
    public let agent: String
    public let tool: String
    public let path: String
    public let ruleID: String
    public let ts: String
    public let scopeText: String?
    enum CodingKeys: String, CodingKey { case id, agent, tool, path, ts; case ruleID = "rule_id"; case scopeText = "scope_text" }
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

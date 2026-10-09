import Foundation

public struct GuardPending: Codable, Identifiable, Sendable {
    public let id: String
    public let agent: String
    public let tool: String
    public let path: String
    public let ruleID: String
    public let ts: String
    public let scopeText: String?
	public let availableScopes: [GuardScopeChoice]?
	public let readerExe: String?
	public let workspace: String?
	public let sessionID: String?
	public init(id: String, agent: String, tool: String, path: String, ruleID: String, ts: String, scopeText: String?, advisor: GuardAdvice?, availableScopes: [GuardScopeChoice]? = nil, readerExe: String? = nil, workspace: String? = nil, sessionID: String? = nil) {
		self.id=id; self.agent=agent; self.tool=tool; self.path=path; self.ruleID=ruleID; self.ts=ts; self.scopeText=scopeText; self.advisor=advisor; self.availableScopes=availableScopes; self.readerExe=readerExe; self.workspace=workspace; self.sessionID=sessionID
	}
    /// The local advisor's recommendation, when one has landed. Advisory only:
    /// the human still decides; this is shown inline to inform the choice.
    public let advisor: GuardAdvice?
    enum CodingKeys: String, CodingKey { case id, agent, tool, path, ts, advisor, workspace; case ruleID = "rule_id"; case scopeText = "scope_text"; case availableScopes = "available_scopes"; case readerExe = "reader_exe"; case sessionID = "session_id" }
}

public struct GuardScopeChoice: Codable, Sendable, Identifiable {
	public let kind: String
	public let expiry: String?
	public var id: String { "\(kind)/\(expiry ?? "")" }
	public var label: String {
		if kind == "session" { return "Allow for this session" }
		return expiry == "7d" ? "Allow for 7 days" : "Allow for 24 hours"
	}
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
	public let expiry: String?
	public init(id: String, verdict: String, scope: String, expiry: String? = nil) {
		self.id=id; self.verdict=verdict; self.scope=scope; self.expiry=expiry
	}
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

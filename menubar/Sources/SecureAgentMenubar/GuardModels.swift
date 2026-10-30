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
	/// The hook's reason line, e.g. what an untrusted-egress session read.
	public let detail: String?
	/// The kinds of send an untrusted-egress request makes (git-push, gh-write,
	/// network-send, mcp:<server>); a kind permission covers all of them.
	public let categories: [String]?
	/// The choice the prompt opens with: the daemon preselects a session
	/// permission for the kind once this session has asked about it before.
	public let defaultScope: GuardScopeChoice?
	/// This session's earlier prompts for the same kinds of send.
	public let repeats: Int?
	public init(id: String, agent: String, tool: String, path: String, ruleID: String, ts: String, scopeText: String?, advisor: GuardAdvice?, availableScopes: [GuardScopeChoice]? = nil, readerExe: String? = nil, workspace: String? = nil, sessionID: String? = nil, detail: String? = nil, categories: [String]? = nil, defaultScope: GuardScopeChoice? = nil, repeats: Int? = nil) {
		self.id=id; self.agent=agent; self.tool=tool; self.path=path; self.ruleID=ruleID; self.ts=ts; self.scopeText=scopeText; self.advisor=advisor; self.availableScopes=availableScopes; self.readerExe=readerExe; self.workspace=workspace; self.sessionID=sessionID; self.detail=detail
		self.categories=categories; self.defaultScope=defaultScope; self.repeats=repeats
	}
    /// The local advisor's recommendation, when one has landed. Advisory only:
    /// the human still decides; this is shown inline to inform the choice.
    public let advisor: GuardAdvice?
    enum CodingKeys: String, CodingKey { case id, agent, tool, path, ts, advisor, workspace, detail, categories, repeats; case ruleID = "rule_id"; case scopeText = "scope_text"; case availableScopes = "available_scopes"; case readerExe = "reader_exe"; case sessionID = "session_id"; case defaultScope = "default_scope" }
}

public struct GuardScopeChoice: Codable, Sendable, Identifiable, Hashable {
	public let kind: String
	public let expiry: String?
	/// The permission covers every send of the request's kinds, not its sinks.
	public let category: Bool?
	public init(kind: String, expiry: String?, category: Bool? = nil) {
		self.kind = kind; self.expiry = expiry; self.category = category
	}
	public var coversKind: Bool { category == true }
	public var id: String { "\(kind)/\(expiry ?? "")\(coversKind ? "/kind" : "")" }
	public var label: String {
		switch kind {
		case "session": return "Allow for this session"
		case "standing": return "Allow always"
		default: return expiry == "7d" ? "Allow for 7 days" : "Allow for 24 hours"
		}
	}
}

/// What a kind of untrusted-egress send is called in prompts and settings.
public enum GuardSendKind {
	/// The kinds Settings tunes; "mcp-send" sets every MCP server without its own mode.
	public static let tunable = ["git-push", "gh-write", "network-send", "mcp-send"]

	public static func label(_ kind: String) -> String {
		switch kind {
		case "git-push": return "git pushes"
		case "gh-write": return "GitHub writes (gh)"
		case "network-send": return "network sends"
		case "mcp-send": return "MCP sends"
		default:
			if kind.hasPrefix("mcp:") { return "\(kind.dropFirst(4)) MCP sends" }
			return kind
		}
	}

	/// "git pushes and GitHub writes (gh)" for a request's kinds; nil for none.
	public static func label(_ kinds: [String]?) -> String? {
		guard let kinds, !kinds.isEmpty else { return nil }
		let names = kinds.map { label($0) }
		return names.count == 1 ? names[0] : names.dropLast().joined(separator: ", ") + " and " + names.last!
	}
}

extension GuardPending {
    var requestFactRows: [(label: String, value: String)] {
        [("Operation", tool), ("Resource", path), ("Workspace", workspace ?? "Unknown"), ("Matched rule", ruleID),
         ("Executable path", readerExe ?? "Unknown; once only"), ("Session", sessionID ?? "Unknown")]
    }

    /// The untrusted inputs an untrusted-egress request names, one per entry,
    /// read from the hook's reason line ("This session read untrusted
    /// content: a; b. It now sends data out: <path>."). nil for any other shape.
    var untrustedSources: [String]? {
        let lead = "This session read untrusted content: "
        guard ruleID == "untrusted-egress", let detail, detail.hasPrefix(lead) else { return nil }
        var read = String(detail.dropFirst(lead.count))
        if let tail = read.range(of: ". It now sends data out: ", options: .backwards) { read = String(read[..<tail.lowerBound]) }
        let sources = read.components(separatedBy: "; ").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
        return sources.isEmpty ? nil : sources
    }

    var requestFacts: String {
        let why = (detail?.isEmpty == false) ? "Why: \(detail!)\n" : ""
        return why + requestFactRows.map { "\($0.label): \($0.value)" }.joined(separator: "\n")
    }

    /// What a session, timed or standing allow grants, shown under the
    /// prompt's Allow button; nil for a scope the request does not offer.
    func grantTerms(scope: String, expiry: String?, category: Bool = false) -> String? {
        guard availableScopes?.contains(where: { $0.kind == scope && $0.expiry == expiry && $0.coversKind == category }) == true else { return nil }
        let sends = ruleID == "untrusted-egress"
        let kinds = category ? GuardSendKind.label(categories) : nil
        if category && kinds == nil { return nil }
        let subject = kinds.map { "all \($0) from this tool in this workspace" } ?? (sends ? "these sends from this tool" : "this file and tool")
        let effect: String
        switch scope {
        case "session": effect = "Allows \(subject) until this session ends."
        case "exact" where expiry == "24h" || expiry == "7d": effect = "Allows \(subject) for \(expiry == "7d" ? "7 days" : "24 hours")."
        case "standing": effect = "Allows \(subject) until you revoke it."
        default: return nil
        }
        let limit = sends ? (category ? "Other kinds of send still ask." : "Other sends still ask.") : "File approval does not authorize network access."
        return "\(effect) Executable signatures are not verified. \(limit) Revoke under Protection → Rules & permissions."
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
    public let scope: String     // once | always | session | exact | standing
	public let expiry: String?
	/// A permission for every send of the request's kinds.
	public let category: Bool?
	public init(id: String, verdict: String, scope: String, expiry: String? = nil, category: Bool? = nil) {
		self.id=id; self.verdict=verdict; self.scope=scope; self.expiry=expiry; self.category = category == true ? true : nil
	}
}

public struct GuardResolveReceipt: Codable, Sendable {
    public let id: String
    public let sessionID: String?
    public let ruleID: String
    public let verdict: String
    public let scope: String
    public let expiry: String?
    public let category: Bool?
    public let at: String
    public let scopeIDs: [String]?
    enum CodingKeys: String, CodingKey {
        case id, verdict, scope, expiry, category, at
        case sessionID = "session_id", ruleID = "rule_id", scopeIDs = "scope_ids"
    }
    public func matches(_ request: GuardResolveRequest) -> Bool {
        id == request.id && !id.isEmpty && verdict == request.verdict && scope == request.scope &&
        (expiry ?? "") == (request.expiry ?? "") && (category == true) == (request.category == true) &&
        ["allow", "deny"].contains(verdict) && ["once", "always", "session", "exact", "standing"].contains(scope) &&
        !ruleID.isEmpty && EventTime.parse(at) != nil && (scopeIDs?.count ?? 0) <= 128 &&
        !(scopeIDs?.contains(where: { $0.isEmpty }) ?? false) &&
        ((scopeIDs?.isEmpty ?? true) || (verdict == "allow" && ["session", "exact", "standing"].contains(scope)))
    }
}

public struct GuardResolveResponse: Decodable, Sendable {
    public let resolved: Bool
    public let receipt: GuardResolveReceipt?
}

public struct GuardDecisionResult: Sendable {
    public let request: GuardResolveRequest
    public let receipt: GuardResolveReceipt?
    public let sessionID: String?
    public let unconfirmed: Bool
    public var title: String { unconfirmed ? "Answer not confirmed" : "Answer submitted" }
    public var detail: String {
        if unconfirmed { return "Check session results and permissions before deciding again. The answer may have reached the daemon." }
        let limit = "Submission does not prove tool receipt, completed access, or saved request history."
        return receipt == nil ? "Detailed receipt unavailable from this daemon. " + limit : limit
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

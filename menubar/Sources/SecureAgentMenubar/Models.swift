import Foundation

public struct AgentSummaryModel: Codable, Identifiable, Sendable {
    /// pid alone can collide across pid reuse while a stale row lingers in the
    /// list; pid+name is still wrong only if the same process is listed twice,
    /// which the tagger's pid-keyed table prevents.
    public var id: String { "\(pid)-\(name)" }
    public let pid: Int32
    public let name: String
    public let exePath: String?
    public let cwd: String?
    /// The family root this process belongs to (itself when it IS the root).
    /// 0/nil on older daemons — treat as its own root then.
    public let rootPid: Int32?
    /// Direct parent pid (nil on older daemons). The tree view uses this to
    /// indent subagents under the session that spawned them.
    public let ppid: Int32?
    /// Process start (RFC3339) — the "created" sort key.
    public let startedAt: String?
    /// Most recent event attributed to this process (RFC3339) — the
    /// "last activity" sort key and the is-it-doing-anything signal.
    public let lastSeenAt: String?
    /// Resident memory in bytes (0/nil when the daemon couldn't read it).
    public let rssBytes: UInt64?
    /// True when this tagged process's parent has already exited (daemon
    /// reports is_orphan) — displayed so a weird-looking row is explainable.
    /// nil (older daemons) reads as "not orphan" here; the row simply shows
    /// nothing rather than a wrong glyph.
    public var isOrphanLike: Bool { isOrphan ?? false }

    public let isOrphan: Bool?

    enum CodingKeys: String, CodingKey {
        case pid
        case name
        case exePath = "exe_path"
        case cwd
        case rootPid = "root_pid"
        case ppid
        case startedAt = "started_at"
        case lastSeenAt = "last_seen_at"
        case rssBytes = "rss_bytes"
        case isOrphan = "is_orphan"
    }

    public init(pid: Int32, name: String, exePath: String? = nil, cwd: String? = nil, rootPid: Int32? = nil,
                ppid: Int32? = nil, startedAt: String? = nil, lastSeenAt: String? = nil, rssBytes: UInt64? = nil,
                isOrphan: Bool? = nil) {
        self.pid = pid
        self.name = name
        self.exePath = exePath
        self.cwd = cwd
        self.rootPid = rootPid
        self.ppid = ppid
        self.startedAt = startedAt
        self.lastSeenAt = lastSeenAt
        self.rssBytes = rssBytes
        self.isOrphan = isOrphan
    }
}

public struct RuleStatModel: Codable, Sendable {
    public let wouldBlock: Int
    public let blocked: Int
    public let legit: Int
    public let suspect: Int
    public let mode: String?

    enum CodingKeys: String, CodingKey {
        case wouldBlock = "would_block"
        case blocked
        case legit
        case suspect
        case mode
    }

    public init(wouldBlock: Int = 0, blocked: Int = 0, legit: Int = 0, suspect: Int = 0, mode: String? = nil) {
        self.wouldBlock = wouldBlock
        self.blocked = blocked
        self.legit = legit
        self.suspect = suspect
        self.mode = mode
    }
}

/// One per-path guard exception (menubar view of guard_path_allows).
public struct GuardPathAllowModel: Codable, Identifiable, Sendable {
    public let agent: String
    public let ruleID: String
    public let path: String
    public let createdAt: String?

    enum CodingKeys: String, CodingKey {
        case agent
        case ruleID = "rule_id"
        case path
        case createdAt = "created_at"
    }

    public init(agent: String, ruleID: String, path: String, createdAt: String? = nil) {
        self.agent = agent
        self.ruleID = ruleID
        self.path = path
        self.createdAt = createdAt
    }

    public var id: String { "\(agent)-\(ruleID)-\(path)" }
}

/// Health of one supervised collector worker (eslogger, netsampler,
/// transcript). Surfaced so a dead/abandoned collector cannot masquerade as
/// healthy — "why are transcripts thin" deserves an on-screen answer.
public struct HealthModel: Codable, Identifiable, Sendable {
    public let name: String
    public let running: Bool
    /// True when the supervisor gave up on this worker (permanent failure or
    /// sustained crash-looping) — it will NOT come back without a restart.
    public let abandoned: Bool
    public let restarts: Int
    public let lastError: String?

    public var id: String { name }
}

public struct StatusResponse: Codable, Sendable {
    public let running: Bool
    public let version: String?
    public let uptime: String
    public let activeAgents: Int
    /// Var (not let): value semantics make this safe, and tests seed agent
    /// lists after constructing a StatusResponse.
    public var agents: [AgentSummaryModel]?
    public let proxyEnabled: Bool?
    public let proxyPort: Int?
    public let uninspectedEgress: Int?
    public let firewallStats: [String: RuleStatModel]?
    /// Total tagged processes across all agent trees (nil on older daemons).
    public let trackedProcesses: Int?
    /// Collector worker health (nil on older daemons).
    public var collectors: [HealthModel]?

    enum CodingKeys: String, CodingKey {
        case running
        case version
        case uptime
        case activeAgents = "active_agents"
        case agents
        case proxyEnabled = "proxy_enabled"
        case proxyPort = "proxy_port"
        case uninspectedEgress = "uninspected_egress"
        case firewallStats = "firewall_stats"
        case trackedProcesses = "tracked_processes"
        case collectors
    }

    public init(running: Bool, uptime: String, activeAgents: Int, agents: [AgentSummaryModel]? = nil, proxyEnabled: Bool? = nil, proxyPort: Int? = nil, uninspectedEgress: Int? = nil, firewallStats: [String: RuleStatModel]? = nil, trackedProcesses: Int? = nil, collectors: [HealthModel]? = nil, version: String? = nil) {
        self.running = running
        self.version = version
        self.uptime = uptime
        self.activeAgents = activeAgents
        self.agents = agents
        self.proxyEnabled = proxyEnabled
        self.proxyPort = proxyPort
        self.uninspectedEgress = uninspectedEgress
        self.firewallStats = firewallStats
        self.trackedProcesses = trackedProcesses
        self.collectors = collectors
    }
}

public struct AdvisorDiscovery: Codable, Sendable {
    public let servers: [DiscoveredServerModel]
    public let managedModels: [String]

    enum CodingKeys: String, CodingKey {
        case servers
        case managedModels = "managed_models"
    }

    public init(servers: [DiscoveredServerModel], managedModels: [String]) {
        self.servers = servers
        self.managedModels = managedModels
    }
}

public struct DiscoveredServerModel: Codable, Identifiable, Sendable {
    public var id: String { endpoint }
    public let endpoint: String
    public let kind: String
    public let models: [String]

    public init(endpoint: String, kind: String, models: [String]) {
        self.endpoint = endpoint
        self.kind = kind
        self.models = models
    }
}

public struct RollupPointModel: Codable, Sendable {
    public let bucket: String
    public let kind: String
    public let count: Int
}

public struct AuditEntryModel: Codable, Sendable {
    public let id: Int
    public let ts: String
    public let action: String
    public let rule: String?
    public let detail: String?
}

public struct AdvisorVerdictModel: Codable, Sendable {
    public let assessment: String?
    public let confidence: Double?
    public let rationale: String
    public let suggestedAction: String?

    enum CodingKeys: String, CodingKey {
        case assessment, confidence, rationale
        case suggestedAction = "suggested_action"
    }
}

public struct FlagModel: Codable, Identifiable, Sendable {
    public let id: String
    public let rule: String
    public let severity: Int
    public let ts: String
    public let pid: Int32
    public let agent: String
    public let evidence: [String]
    /// Harness session that produced the flag — the evidence-chain link that
    /// survives PID reuse. Empty for OS-level signals.
    public let sessionId: String?
    /// Local advisor triage verdict when one exists. Advisory only.
    public let advisor: AdvisorVerdictModel?
    /// True when the operator applied a disposition on this flag — it stops
    /// counting as critical and renders dimmed instead of endlessly red.
    public let acknowledged: Bool?

    enum CodingKeys: String, CodingKey {
        case id, rule, severity, ts, pid, agent, evidence, advisor
        case sessionId = "session_id"
        case acknowledged
    }

    public init(id: String, rule: String, severity: Int, ts: String, pid: Int32, agent: String,
                evidence: [String], sessionId: String? = nil, advisor: AdvisorVerdictModel? = nil,
                acknowledged: Bool? = nil) {
        self.id = id
        self.rule = rule
        self.severity = severity
        self.ts = ts
        self.pid = pid
        self.agent = agent
        self.evidence = evidence
        self.sessionId = sessionId
        self.advisor = advisor
        self.acknowledged = acknowledged
    }
}

public struct EventModel: Codable, Identifiable, Sendable {
    /// kind-pid-ts collided for same-second duplicates; ts carries nanoseconds
    /// from Go's RFC3339Nano, and the path/host tail separates the rest.
    public var id: String {
        "\(kind)-\(pid)-\(ts)-\(path ?? "")-\(remoteHost ?? "")\(remotePort.map(String.init) ?? "")-\(sessionId ?? "")"
    }
    public let kind: Int
    public let ts: String
    public let pid: Int32
    public let exePath: String?
    public let path: String?
    public let remoteHost: String?
    public let remotePort: Int?
    public let detail: String?
    public let sessionId: String?

    enum CodingKeys: String, CodingKey {
        case kind
        case ts
        case pid
        case exePath = "exe_path"
        case path
        case remoteHost = "remote_host"
        case remotePort = "remote_port"
        case detail
        case sessionId = "session_id"
    }

    public init(kind: Int, ts: String, pid: Int32, exePath: String? = nil, path: String? = nil, remoteHost: String? = nil, remotePort: Int? = nil, detail: String? = nil, sessionId: String? = nil) {
        self.kind = kind
        self.ts = ts
        self.pid = pid
        self.exePath = exePath
        self.path = path
        self.remoteHost = remoteHost
        self.remotePort = remotePort
        self.detail = detail
        self.sessionId = sessionId
    }
}

public struct RotateItemModel: Codable, Identifiable, Sendable {
    public let id: String
    public let category: String
    public let name: String
    public let path: String?
    public let risk: String
    public let description: String
    public let action: String

    public init(id: String, category: String, name: String, path: String? = nil, risk: String, description: String, action: String) {
        self.id = id
        self.category = category
        self.name = name
        self.path = path
        self.risk = risk
        self.description = description
        self.action = action
    }
}

public struct IncidentWorkflowModel: Codable, Sendable {
    public let status: String // "open" | "acknowledged" | "resolved"
}

public struct IncidentReportModel: Codable, Identifiable, Sendable {
    public let id: String
    public let flagId: String
    public let pid: Int32
    public let agent: String
    public let timestamp: String
    public let rule: String
    public let summary: String
    public let risk: String
    public let touchedFiles: [String]
    public let connections: [String]
    public let rotateList: [RotateItemModel]
    /// Lifecycle state (open/acknowledged/resolved) — sibling key in the
    /// daemon's incident payload; nil for older daemons.
    public let workflow: IncidentWorkflowModel?

    enum CodingKeys: String, CodingKey {
        case id
        case flagId = "flag_id"
        case pid
        case agent
        case timestamp
        case rule
        case summary
        case risk
        case touchedFiles = "touched_files"
        case connections
        case rotateList = "rotate_list"
        case workflow
    }

    public init(id: String, flagId: String, pid: Int32, agent: String, timestamp: String, rule: String, summary: String, risk: String, touchedFiles: [String], connections: [String], rotateList: [RotateItemModel], workflow: IncidentWorkflowModel? = nil) {
        self.id = id
        self.flagId = flagId
        self.pid = pid
        self.agent = agent
        self.timestamp = timestamp
        self.rule = rule
        self.summary = summary
        self.risk = risk
        self.touchedFiles = touchedFiles
        self.connections = connections
        self.rotateList = rotateList
        self.workflow = workflow
    }
}

import Foundation

public struct ResourceSnapshotModel: Codable, Sendable {
    public let host: HostPressureModel?
    public let sessions: [ResourceSessionModel]?

    public init(host: HostPressureModel?, sessions: [ResourceSessionModel]? = nil) {
        self.host = host
        self.sessions = sessions
    }
}

public struct ResourceSessionModel: Codable, Sendable {
    public let key: String
    public let name: String
    /// "infra" for shared infrastructure (IDEs, model servers); nil/"agent"
    /// for real coding agents. Nil on older daemons.
    public let kind: String?
    public let control: ResourceSessionControlModel?

    /// Infra sessions render as shared infrastructure, not agent sessions.
    public var isInfra: Bool { kind == "infra" }

    public init(key: String, name: String, kind: String? = nil, control: ResourceSessionControlModel? = nil) {
        self.key = key
        self.name = name
        self.kind = kind
        self.control = control
    }
}

public struct ResourceSessionControlModel: Codable, Sendable {
    public let state: String
    public let pendingID: String?
    public let lastAction: String?
    public let lastError: String?
    public let nextAction: String?
    public let paused: Bool?

    enum CodingKeys: String, CodingKey {
        case state
        case pendingID = "pending_id"
        case lastAction = "last_action"
        case lastError = "last_error"
        case nextAction = "next_action"
        case paused
    }

    public init(state: String, pendingID: String? = nil, lastAction: String? = nil,
                lastError: String? = nil, nextAction: String? = nil, paused: Bool? = nil) {
        self.state = state
        self.pendingID = pendingID
        self.lastAction = lastAction
        self.lastError = lastError
        self.nextAction = nextAction
        self.paused = paused
    }
}

public struct ResourceInterventionNotice: Equatable, Sendable {
    public let sessionKey: String
    public let sessionName: String
    public let state: String
    public let action: String?
    public let error: String?
}

public struct HostPressureModel: Codable, Sendable {
    public let totalMemoryBytes: UInt64?
    public let freeMemoryBytes: UInt64?
    public let availableMemoryBytes: UInt64?
    public let compressedMemoryBytes: UInt64?
    public let usedMemoryBytes: UInt64?
    public let agentMemoryBytes: UInt64?
    public let nonAgentMemoryBytes: UInt64?
    public let swapTotalBytes: UInt64?
    public let swapUsedBytes: UInt64?
    public let headroomPercent: Double?
    public let agentMemoryPercent: Double?
    public let systemCPUPercent: Double?
    public let agentCPUPercent: Double?
    public let nonAgentCPUPercent: Double?
    public let load1: Double?
    public let logicalCPUCount: Int?
    public let memoryPressure: String
    public let thermalState: String
    public let headroomScore: Int
    public let capacity: String

    enum CodingKeys: String, CodingKey {
        case totalMemoryBytes = "total_memory_bytes"
        case freeMemoryBytes = "free_memory_bytes"
        case availableMemoryBytes = "available_memory_bytes"
        case compressedMemoryBytes = "compressed_memory_bytes"
        case usedMemoryBytes = "used_memory_bytes"
        case agentMemoryBytes = "agent_memory_bytes"
        case nonAgentMemoryBytes = "non_agent_memory_bytes"
        case swapTotalBytes = "swap_total_bytes"
        case swapUsedBytes = "swap_used_bytes"
        case headroomPercent = "headroom_percent"
        case agentMemoryPercent = "agent_memory_percent"
        case systemCPUPercent = "system_cpu_percent"
        case agentCPUPercent = "agent_cpu_percent"
        case nonAgentCPUPercent = "non_agent_cpu_percent"
        case load1 = "load_1"
        case logicalCPUCount = "logical_cpu_count"
        case memoryPressure = "memory_pressure"
        case thermalState = "thermal_state"
        case headroomScore = "headroom_score"
        case capacity
    }

    public init(totalMemoryBytes: UInt64? = nil, freeMemoryBytes: UInt64? = nil,
                availableMemoryBytes: UInt64? = nil, compressedMemoryBytes: UInt64? = nil,
                usedMemoryBytes: UInt64? = nil, agentMemoryBytes: UInt64? = nil,
                nonAgentMemoryBytes: UInt64? = nil, swapTotalBytes: UInt64? = nil,
                swapUsedBytes: UInt64? = nil, headroomPercent: Double? = nil,
                agentMemoryPercent: Double? = nil, systemCPUPercent: Double? = nil,
                agentCPUPercent: Double? = nil, nonAgentCPUPercent: Double? = nil,
                load1: Double? = nil, logicalCPUCount: Int? = nil,
                memoryPressure: String = "unknown", thermalState: String = "unknown",
                headroomScore: Int = 0, capacity: String = "unknown") {
        self.totalMemoryBytes = totalMemoryBytes
        self.freeMemoryBytes = freeMemoryBytes
        self.availableMemoryBytes = availableMemoryBytes
        self.compressedMemoryBytes = compressedMemoryBytes
        self.usedMemoryBytes = usedMemoryBytes
        self.agentMemoryBytes = agentMemoryBytes
        self.nonAgentMemoryBytes = nonAgentMemoryBytes
        self.swapTotalBytes = swapTotalBytes
        self.swapUsedBytes = swapUsedBytes
        self.headroomPercent = headroomPercent
        self.agentMemoryPercent = agentMemoryPercent
        self.systemCPUPercent = systemCPUPercent
        self.agentCPUPercent = agentCPUPercent
        self.nonAgentCPUPercent = nonAgentCPUPercent
        self.load1 = load1
        self.logicalCPUCount = logicalCPUCount
        self.memoryPressure = memoryPressure
        self.thermalState = thermalState
        self.headroomScore = headroomScore
        self.capacity = capacity
    }
}

public struct AgentSummaryModel: Codable, Identifiable, Sendable {
    /// pid alone can collide across pid reuse while a stale row lingers in the
    /// list; pid+name is still wrong only if the same process is listed twice,
    /// which the tagger's pid-keyed table prevents.
    public var id: String { "\(pid)-\(name)" }
    public let pid: Int32
    public let name: String
    /// "infra" for shared infrastructure (IDEs, model servers); nil (older
    /// daemons) reads as a regular agent.
    public let kind: String?
    public var isInfra: Bool { kind == "infra" }
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
    /// Current CPU use as a percentage of one core. Values may exceed 100
    /// when a process uses multiple cores; nil means unavailable.
    public let cpuPercent: Double?
    /// True when this tagged process's parent has already exited (daemon
    /// reports is_orphan) — displayed so a weird-looking row is explainable.
    /// nil (older daemons) reads as "not orphan" here; the row simply shows
    /// nothing rather than a wrong glyph.
    public var isOrphanLike: Bool { isOrphan ?? false }

    public let isOrphan: Bool?

    enum CodingKeys: String, CodingKey {
        case pid
        case name
        case kind
        case exePath = "exe_path"
        case cwd
        case rootPid = "root_pid"
        case ppid
        case startedAt = "started_at"
        case lastSeenAt = "last_seen_at"
        case rssBytes = "rss_bytes"
        case cpuPercent = "cpu_percent"
        case isOrphan = "is_orphan"
    }

    public init(pid: Int32, name: String, kind: String? = nil, exePath: String? = nil, cwd: String? = nil, rootPid: Int32? = nil,
                ppid: Int32? = nil, startedAt: String? = nil, lastSeenAt: String? = nil, rssBytes: UInt64? = nil,
                isOrphan: Bool? = nil, cpuPercent: Double? = nil) {
        self.pid = pid
        self.name = name
        self.kind = kind
        self.exePath = exePath
        self.cwd = cwd
        self.rootPid = rootPid
        self.ppid = ppid
        self.startedAt = startedAt
        self.lastSeenAt = lastSeenAt
        self.rssBytes = rssBytes
        self.isOrphan = isOrphan
        self.cpuPercent = cpuPercent
    }

    /// Glance label: the project folder, falling back to the harness name.
    public var cwdLeaf: String {
        guard let cwd, !cwd.isEmpty else { return name }
        return (cwd as NSString).lastPathComponent
    }
}

/// One session tree as emitted by the daemon (`trees` on /status).
public struct AgentTreeModel: Codable, Sendable {
    public let root: AgentSummaryModel
    public let children: [AgentSummaryModel]
    public let rssBytes: UInt64?
    public let lastSeenAt: String?
    public let cpuPercent: Double?

    enum CodingKeys: String, CodingKey {
        case root, children
        case rssBytes = "rss_bytes"
        case lastSeenAt = "last_seen_at"
        case cpuPercent = "cpu_percent"
    }

    public init(root: AgentSummaryModel, children: [AgentSummaryModel] = [], rssBytes: UInt64? = nil,
                lastSeenAt: String? = nil, cpuPercent: Double? = nil) {
        self.root = root
        self.children = children
        self.rssBytes = rssBytes
        self.lastSeenAt = lastSeenAt
        self.cpuPercent = cpuPercent
    }
}

public struct RuleStatModel: Codable, Sendable {
    public let wouldBlock: Int
    public let blocked: Int
    public let legit: Int
    public let suspect: Int
    public let mode: String?
    public let type: String?

    enum CodingKeys: String, CodingKey {
        case wouldBlock = "would_block"
        case blocked
        case legit
        case suspect
        case mode
        case type
    }

    public init(wouldBlock: Int = 0, blocked: Int = 0, legit: Int = 0, suspect: Int = 0, mode: String? = nil, type: String? = nil) {
        self.wouldBlock = wouldBlock
        self.blocked = blocked
        self.legit = legit
        self.suspect = suspect
        self.mode = mode
        self.type = type
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
    /// RFC3339 of the worker's most recent published event — running but
    /// silent is the "monitor gone blind" signal. Nil on older daemons.
    public let lastProduced: String?

    public var id: String { name }

    enum CodingKeys: String, CodingKey {
        case name, running, abandoned, restarts
        case lastError = "last_error"
        case lastProduced = "last_produced"
    }
}

/// How many running harnesses the daemon is actually seeing (`coverage` in
/// /status). The monitor reporting its own blindness.
public struct CoverageModel: Codable, Sendable {
    public let harnessesActive: Int
    public let harnessesSeen: Int

    enum CodingKeys: String, CodingKey {
        case harnessesActive = "harnesses_active"
        case harnessesSeen = "harnesses_seen"
    }
}

public struct StatusResponse: Codable, Sendable {
    public let running: Bool
    public let version: String?
    public let uptime: String
    public let activeAgents: Int
    /// Distinct infra tree roots (IDEs, local model servers) — shown beside,
    /// never inside, activeAgents. Nil on older daemons.
    public let infraCount: Int?
    /// Var (not let): value semantics make this safe, and tests seed agent
    /// lists after constructing a StatusResponse.
    public var agents: [AgentSummaryModel]?
    /// Daemon-grouped session trees. Nil on older daemons — the popover
    /// regroups the flat list then.
    public var trees: [AgentTreeModel]?
    public let proxyEnabled: Bool?
    public let proxyPort: Int?
    public let uninspectedEgress: Int?
    public var firewallStats: [String: RuleStatModel]?
    /// Total tagged processes across all agent trees (nil on older daemons).
    public let trackedProcesses: Int?
    /// Collector worker health (nil on older daemons).
    public var collectors: [HealthModel]?
    /// Live advisor health (nil on older daemons): lets the UI say "advisor
    /// offline" instead of offering actions that silently do nothing.
    public let advisorHealth: AdvisorHealthModel?
    public var fleetConfigured: Bool?
    /// Harness coverage (nil on older daemons).
    public let coverage: CoverageModel?

    enum CodingKeys: String, CodingKey {
        case running
        case version
        case uptime
        case activeAgents = "active_agents"
        case infraCount = "infra_count"
        case agents
        case trees
        case proxyEnabled = "proxy_enabled"
        case proxyPort = "proxy_port"
        case uninspectedEgress = "uninspected_egress"
        case firewallStats = "firewall_stats"
        case trackedProcesses = "tracked_processes"
        case collectors
        case advisorHealth = "advisor_health"
        case fleetConfigured = "fleet_configured"
        case coverage
    }

    public init(running: Bool, uptime: String, activeAgents: Int, infraCount: Int? = nil, agents: [AgentSummaryModel]? = nil, trees: [AgentTreeModel]? = nil, proxyEnabled: Bool? = nil, proxyPort: Int? = nil, uninspectedEgress: Int? = nil, firewallStats: [String: RuleStatModel]? = nil, trackedProcesses: Int? = nil, collectors: [HealthModel]? = nil, version: String? = nil, advisorHealth: AdvisorHealthModel? = nil, fleetConfigured: Bool? = nil, coverage: CoverageModel? = nil) {
        self.running = running
        self.version = version
        self.uptime = uptime
        self.activeAgents = activeAgents
        self.infraCount = infraCount
        self.agents = agents
        self.trees = trees
        self.proxyEnabled = proxyEnabled
        self.proxyPort = proxyPort
        self.uninspectedEgress = uninspectedEgress
        self.firewallStats = firewallStats
        self.trackedProcesses = trackedProcesses
        self.collectors = collectors
        self.advisorHealth = advisorHealth
        self.fleetConfigured = fleetConfigured
        self.coverage = coverage
    }
}

/// The daemon's advisor health snapshot (`advisor_health` in /status).
public struct AdvisorHealthModel: Codable, Sendable {
    public let enabled: Bool
    public let circuitOpen: Bool?
    public let lastError: String?
    public let queueDepth: Int?
    public let model: String?

    enum CodingKeys: String, CodingKey {
        case enabled
        case circuitOpen = "circuit_open"
        case lastError = "last_error"
        case queueDepth = "queue_depth"
        case model
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

/// The daemon's notification policy: a default severity bar plus per-rule
/// overrides (true = always notify, false = never). The menubar and the web
/// console read the same store, so one choice silences both surfaces.
public struct NotifyRulesResponse: Codable, Sendable {
    public let defaultMinSeverity: Int
    public let overrides: [String: Bool]

    enum CodingKeys: String, CodingKey {
        case defaultMinSeverity = "default_min_severity"
        case overrides
    }

    /// Older daemons (pre-/notify/rules) answer 404 — degrade to the shipped
    /// default policy rather than an error.
    public static let fallback = NotifyRulesResponse(defaultMinSeverity: 3, overrides: [:])
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

    /// Copy with acknowledged=true — the local echo of a successful dismiss,
    /// so the flag leaves the needs-action list without waiting for a poll.
    public func acknowledgedCopy() -> FlagModel {
        FlagModel(id: id, rule: rule, severity: severity, ts: ts, pid: pid, agent: agent,
                  evidence: evidence, sessionId: sessionId, advisor: advisor, acknowledged: true)
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

import Foundation

public struct StatusResponse: Codable, Sendable {
    public let running: Bool
    public let uptime: String
    public let activeAgents: Int
    public let proxyEnabled: Bool?
    public let proxyPort: Int?

    enum CodingKeys: String, CodingKey {
        case running
        case uptime
        case activeAgents = "active_agents"
        case proxyEnabled = "proxy_enabled"
        case proxyPort = "proxy_port"
    }

    public init(running: Bool, uptime: String, activeAgents: Int, proxyEnabled: Bool? = nil, proxyPort: Int? = nil) {
        self.running = running
        self.uptime = uptime
        self.activeAgents = activeAgents
        self.proxyEnabled = proxyEnabled
        self.proxyPort = proxyPort
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

    public init(id: String, rule: String, severity: Int, ts: String, pid: Int32, agent: String, evidence: [String]) {
        self.id = id
        self.rule = rule
        self.severity = severity
        self.ts = ts
        self.pid = pid
        self.agent = agent
        self.evidence = evidence
    }
}

public struct EventModel: Codable, Identifiable, Sendable {
    public var id: String { "\(kind)-\(pid)-\(ts)" }
    public let kind: Int
    public let ts: String
    public let pid: Int32
    public let exePath: String?
    public let path: String?
    public let remoteHost: String?
    public let remotePort: Int?
    public let detail: String?

    enum CodingKeys: String, CodingKey {
        case kind
        case ts
        case pid
        case exePath = "exe_path"
        case path
        case remoteHost = "remote_host"
        case remotePort = "remote_port"
        case detail
    }

    public init(kind: Int, ts: String, pid: Int32, exePath: String? = nil, path: String? = nil, remoteHost: String? = nil, remotePort: Int? = nil, detail: String? = nil) {
        self.kind = kind
        self.ts = ts
        self.pid = pid
        self.exePath = exePath
        self.path = path
        self.remoteHost = remoteHost
        self.remotePort = remotePort
        self.detail = detail
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
    }

    public init(id: String, flagId: String, pid: Int32, agent: String, timestamp: String, rule: String, summary: String, risk: String, touchedFiles: [String], connections: [String], rotateList: [RotateItemModel]) {
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
    }
}

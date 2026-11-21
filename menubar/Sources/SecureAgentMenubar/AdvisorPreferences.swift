import Foundation

/// Edits only advisor-owned scalar fields; unsupported YAML stays untouched.
struct AdvisorPreferences: Equatable, Sendable {
    var timeoutMS = 60000
    var classifierEndpoint = ""
    var classifierModel = "kev-latest"
    var debug = false

    private static let block = "advisor"

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

    /// A loopback base URL, including any server path prefix.
    static func normalizedLoopback(_ raw: String) -> String? {
        var text = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        if text.isEmpty { return nil }
        if !text.contains("://") { text = "http://" + text }
        guard isLoopbackEndpoint(text), var url = URLComponents(string: text),
              let scheme = url.scheme?.lowercased(), let host = url.host?.lowercased() else { return nil }
        if let port = url.port, !(1...65535).contains(port) { return nil }
        url.scheme = scheme
        url.host = host
        if url.percentEncodedPath == "/" { url.percentEncodedPath = "" }
        return url.string
    }

    /// Keep simple HTTP endpoints compact without losing other URL components.
    static func displayAddress(_ endpoint: String) -> String {
        guard let url = URLComponents(string: endpoint), url.scheme?.lowercased() == "http",
              url.percentEncodedPath.isEmpty || url.percentEncodedPath == "/",
              url.user == nil, url.password == nil, url.query == nil, url.fragment == nil,
              let host = url.host else { return endpoint }
        let shown = host.contains(":") && !host.hasPrefix("[") ? "[\(host)]" : host
        if let port = url.port { return "\(shown):\(port)" }
        return shown
    }

    static func read(_ yaml: String) throws -> Self {
        let document = ConfigDocument(yaml)
        var p = Self()
        if let value = try document.scalar("timeout_ms", in: block)?.text {
            guard let n = Int(value), n > 0 else { throw PreferenceError.timeout }
            p.timeoutMS = n
        }
        if let value = try document.scalar("classifier_endpoint", in: block)?.text { p.classifierEndpoint = value }
        if let value = try document.scalar("classifier_model", in: block)?.text { p.classifierModel = value }
        if let value = try document.scalar("debug", in: block)?.text {
            guard value == "true" || value == "false" else { throw PreferenceError.unsupported }
            p.debug = value == "true"
        }
        return p
    }

    /// The saved model choice: how the advisor is served, its endpoint and its model.
    static func persistedChoice(_ yaml: String) -> (mode: String?, endpoint: String?, model: String?) {
        let document = ConfigDocument(yaml)
        func value(_ key: String) -> String? { (try? document.scalar(key, in: block))?.text }
        let managed = value("managed").map { $0 == "true" }
        let endpoint = value("endpoint")
        let model = managed == true ? value("managed_model") ?? value("model") : value("model") ?? value("managed_model")
        // The canonical existing-server writer omits managed; the daemon
        // treats that absence as unmanaged rather than unconfigured.
        let hasExistingConfig = endpoint?.isEmpty == false || value("model")?.isEmpty == false
        let mode = managed.map { $0 ? "managed" : "existing" } ?? (hasExistingConfig ? "existing" : nil)
        return (mode, endpoint, model)
    }

    func updating(_ yaml: String) throws -> String {
        _ = try Self.read(yaml)
        guard timeoutMS > 0 else { throw PreferenceError.timeout }
        guard classifierEndpoint.isEmpty || Self.isLoopbackEndpoint(classifierEndpoint) else { throw PreferenceError.endpoint }
        return try Self.patch(yaml, fields: [
            ("timeout_ms", String(timeoutMS)), ("classifier_endpoint", ConfigDocument.quoted(classifierEndpoint)),
            ("classifier_model", ConfigDocument.quoted(classifierModel)), ("debug", debug ? "true" : "false")
        ])
    }

    static func settingModel(_ yaml: String, managed: Bool, endpoint: String?, model: String) throws -> String {
        _ = try read(yaml)
        if !managed && !isLoopbackEndpoint(endpoint ?? SetupManager.advisorEndpoint) { throw PreferenceError.endpoint }
        var fields: [(String, String?)] = [("enabled", "true"),
            ("managed", managed ? "true" : nil), ("managed_model", managed ? ConfigDocument.quoted(model) : nil),
            ("endpoint", managed ? nil : ConfigDocument.quoted(endpoint ?? SetupManager.advisorEndpoint)),
            ("model", managed ? nil : ConfigDocument.quoted(model))]
        if try ConfigDocument(yaml).scalar("timeout_ms", in: block) == nil { fields.append(("timeout_ms", "60000")) }
        return try patch(yaml, fields: fields)
    }

    static func settingEnabled(_ yaml: String, enabled: Bool) throws -> String {
        _ = try read(yaml)
        var fields: [(String, String?)] = [("enabled", enabled ? "true" : "false")]
        if try !ConfigDocument(yaml).hasBlock(block) {
            fields += [("endpoint", ConfigDocument.quoted(SetupManager.advisorEndpoint)), ("model", ConfigDocument.quoted("")), ("timeout_ms", "60000")]
        }
        return try patch(yaml, fields: fields)
    }

    private static func patch(_ yaml: String, fields: [(String, String?)]) throws -> String {
        try fields.reduce(ConfigDocument(yaml)) { document, field in
            if let value = field.1 { try document.setting(field.0, raw: value, in: block) } else { try document.removing(field.0, in: block) }
        }.text
    }
}

/// Which discovered model names can write an analysis. Matches the daemon's
/// chat filter: embeddings, speech and component checkpoints are listed but
/// are not the default.
enum AdvisorModelList {
    private static let notChat = ["embed", "ocr", "rerank", "whisper", "tts", "music", "tokenizer", "encoder", "decoder", "aligner", "spkr"]

    static func isChat(_ name: String) -> Bool {
        let lower = name.lowercased()
        if lower.count >= 10, lower.allSatisfy(\.isHexDigit) { return false }
        return !notChat.contains { lower.contains($0) }
    }

    static func ordered(_ models: [String]) -> (chat: [String], other: [String]) {
        (models.filter(isChat), models.filter { !isChat($0) })
    }

    /// Keeps an explicit choice. An empty choice picks the first chat model,
    /// so an alphabetically first embedding model is not the analysis model.
    static func preferred(in models: [String], keeping current: String) -> String {
        if models.contains(current) { return current }
        return models.first(where: isChat) ?? models.first ?? ""
    }
}

/// What Automatic analysis is doing. Built from the saved config and the
/// daemon's advisor health, so the section never has to imply its state
/// from which buttons are on screen.
struct AnalysisStanding: Equatable {
    enum Kind: Equatable {
        case off, on, working, paused, notRunning, unreported
    }

    var kind: Kind
    var headline: String
    var detail: String
    var symbol: String

    struct Health: Equatable {
        var enabled = false
        var circuitOpen = false
        var lastError = ""
        var queueDepth = 0
        var model = ""
        var state = ""
    }

    static func report(configured: Bool, mode: String?, endpoint: String?, model: String?, health: Health?, reported: Bool, unapplied: Bool) -> AnalysisStanding {
        let saved = savedLine(mode: mode, endpoint: endpoint, model: model)
        let standing: AnalysisStanding
        if !configured {
            standing = AnalysisStanding(
                kind: .off, headline: "Off",
                detail: saved == "No model saved" ? "Automatic analysis is off." : "Automatic analysis is off. Saved choice: \(saved).",
                symbol: "circle")
        } else if !reported || health == nil {
            standing = AnalysisStanding(
                kind: .unreported, headline: "On, monitor not reporting",
                detail: "\(saved). The monitor has not reported whether analysis is running.",
                symbol: "exclamationmark.triangle.fill")
        } else if let health, !health.enabled {
            let why = health.lastError.isEmpty ? "The monitor is not running analysis." : health.lastError
            standing = AnalysisStanding(
                kind: .notRunning, headline: "On in settings, not running",
                detail: "\(why) \(saved).",
                symbol: "exclamationmark.triangle.fill")
        } else if let health, health.circuitOpen {
            let why = health.lastError.isEmpty
                ? "The model server failed repeatedly. Analysis waits before trying again."
                : health.lastError
            standing = AnalysisStanding(kind: .paused, headline: "Paused", detail: why, symbol: "pause.circle.fill")
        } else if let health {
            standing = workingOrOn(health, saved: saved)
        } else {
            standing = AnalysisStanding(
                kind: .unreported, headline: "On, monitor not reporting",
                detail: saved, symbol: "exclamationmark.triangle.fill")
        }
        guard unapplied, configured else { return standing }
        var noted = standing
        noted.detail += noted.detail.hasSuffix(".") ? " " : ". "
        noted.detail += "The choices above are not applied yet."
        return noted
    }

    private static func workingOrOn(_ health: Health, saved: String) -> AnalysisStanding {
        let live = health.model.isEmpty ? saved : health.model
        switch health.state {
        case "preparing":
            return AnalysisStanding(kind: .working, headline: "Preparing an analysis", detail: live, symbol: "arrow.triangle.2.circlepath")
        case "answering":
            return AnalysisStanding(kind: .working, headline: "Writing an analysis", detail: live, symbol: "arrow.triangle.2.circlepath")
        case "inspecting":
            return AnalysisStanding(kind: .working, headline: "Reading evidence", detail: live, symbol: "arrow.triangle.2.circlepath")
        case "idle", "":
            var detail = live
            if health.queueDepth == 1 { detail += " · 1 waiting" }
            else if health.queueDepth > 1 { detail += " · \(health.queueDepth) waiting" }
            return AnalysisStanding(kind: .on, headline: "On", detail: detail, symbol: "checkmark.circle.fill")
        default:
            return AnalysisStanding(kind: .on, headline: "On", detail: "\(live) · \(health.state)", symbol: "checkmark.circle.fill")
        }
    }

    static func savedLine(mode: String?, endpoint: String?, model: String?) -> String {
        let name = model?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        if mode == "managed" {
            return name.isEmpty ? "Managed model, none saved" : "Managed · \(name)"
        }
        let address = endpoint.map(AdvisorPreferences.displayAddress).flatMap { $0.isEmpty ? nil : $0 }
        if mode == "existing" || address != nil || !name.isEmpty {
            switch (address, name.isEmpty) {
            case let (address?, false): return "\(address) · \(name)"
            case let (address?, true): return address
            case (nil, false): return name
            case (nil, true): return "No model saved"
            }
        }
        return "No model saved"
    }
}

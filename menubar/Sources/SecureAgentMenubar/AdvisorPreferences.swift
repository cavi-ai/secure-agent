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

import SwiftUI

struct FirewallPattern: Codable, Identifiable, Sendable, Equatable {
    var id: String
    var type: String
    var re: String
    var mode: String
}

struct GuardPathRule: Codable, Identifiable, Sendable, Equatable {
    var id: String
    var paths: [String]
    var mode: String
    var readSensitive: Bool
    enum CodingKeys: String, CodingKey { case id, paths, mode; case readSensitive = "read_sensitive" }
}

struct GuardPolicy: Codable, Sendable {
    var rules: [GuardPathRule]
    var dirScan: [[String]]
    enum CodingKeys: String, CodingKey { case rules; case dirScan = "dir_scan" }
}

extension DaemonClient {
    func fetchFirewallPatterns() async throws -> [FirewallPattern] {
        try await getDecodable("/firewall/patterns")
    }

    func editFirewallPattern(op: String, id: String?, pattern: FirewallPattern?) async throws -> [FirewallPattern] {
        struct Edit: Encodable { let op: String; let id: String?; let pattern: FirewallPattern? }
        let data = try await request(method: "POST", path: "/firewall/patterns",
                                     body: JSONEncoder().encode(Edit(op: op, id: id, pattern: pattern)), includePolicyError: true)
        return try JSONDecoder().decode([FirewallPattern].self, from: data)
    }

    func fetchGuardPolicy() async throws -> GuardPolicy { try await getDecodable("/guard/config") }

    func editGuardPath(op: String, id: String?, rule: GuardPathRule?) async throws -> GuardPolicy {
        struct Edit: Encodable { let op: String; let id: String?; let rule: GuardPathRule? }
        let data = try await request(method: "POST", path: "/guard/config",
                                     body: JSONEncoder().encode(Edit(op: op, id: id, rule: rule)), includePolicyError: true)
        return try JSONDecoder().decode(GuardPolicy.self, from: data)
    }
}

@MainActor
final class ProtectionSettings: ObservableObject {
    @Published private(set) var patterns: [FirewallPattern]?
    @Published private(set) var guardPolicy: GuardPolicy?
    @Published private(set) var firewallError: String?
    @Published private(set) var guardError: String?
    @Published private(set) var saving = false
    @Published private(set) var removedPatternIDs: Set<String> = []
    let client: DaemonClient

    init(client: DaemonClient = DaemonClient()) { self.client = client }

    func load() async {
        do { patterns = try await client.fetchFirewallPatterns(); firewallError = nil }
        catch { firewallError = error.localizedDescription }
        do { guardPolicy = try await client.fetchGuardPolicy(); guardError = nil }
        catch { guardError = error.localizedDescription }
    }

    func save(_ edit: ProtectionRuleEdit) async throws {
        guard !saving else { throw DaemonClientError.policyRejected("Another rule change is still being saved.") }
        saving = true
        defer { saving = false }
        let op = edit.originalID == nil ? "add" : "edit"
        if edit.kind == .firewall {
            patterns = try await client.editFirewallPattern(op: op, id: edit.originalID,
                pattern: FirewallPattern(id: edit.ruleID.trimmingCharacters(in: .whitespacesAndNewlines),
                                         type: edit.secretType, re: edit.expression, mode: edit.mode))
            firewallError = nil
            removedPatternIDs.remove(edit.ruleID)
        } else {
            guardPolicy = try await client.editGuardPath(op: op, id: edit.originalID,
                rule: GuardPathRule(id: edit.ruleID.trimmingCharacters(in: .whitespacesAndNewlines),
                                    paths: edit.paths, mode: edit.mode, readSensitive: edit.readSensitive))
            guardError = nil
        }
    }

    func remove(_ edit: ProtectionRuleEdit) async throws {
        guard !saving else { throw DaemonClientError.policyRejected("Another rule change is still being saved.") }
        saving = true
        defer { saving = false }
        if edit.kind == .firewall {
            patterns = try await client.editFirewallPattern(op: "remove", id: edit.ruleID, pattern: nil)
            removedPatternIDs.insert(edit.ruleID)
            firewallError = nil
        } else {
            guardPolicy = try await client.editGuardPath(op: "remove", id: edit.ruleID, rule: nil)
            guardError = nil
        }
    }
}

struct ProtectionRuleEdit: Identifiable {
    enum Kind { case firewall, guardPath }
    let id = UUID()
    var kind: Kind
    var originalID: String?
    var ruleID = ""
    var expression = ""
    var secretType = "vendor-key"
    var mode = "monitor"
    var readSensitive = true
    var paths: [String] {
        expression.components(separatedBy: .newlines)
            .map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
    }

    init(kind: Kind) { self.kind = kind }
    init(pattern: FirewallPattern) {
        kind = .firewall; originalID = pattern.id; ruleID = pattern.id
        expression = pattern.re; secretType = pattern.type; mode = pattern.mode
    }
    init(rule: GuardPathRule) {
        kind = .guardPath; originalID = rule.id; ruleID = rule.id
        expression = rule.paths.joined(separator: "\n"); mode = rule.mode; readSensitive = rule.readSensitive
    }
}

struct ProtectionRuleEditor: View {
    @State var edit: ProtectionRuleEdit
    @ObservedObject var settings: ProtectionSettings
    var didSave: () -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var error: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("\(edit.originalID == nil ? "Add" : "Edit") \(edit.kind == .firewall ? "firewall rule" : "guarded path")")
                .font(.title2.weight(.semibold))
            Form {
                TextField("Rule ID", text: $edit.ruleID).disabled(edit.originalID != nil)
                if edit.kind == .firewall {
                    Picker("Secret type", selection: $edit.secretType) {
                        Text("Vendor key").tag("vendor-key")
                        Text("Cloud key").tag("cloud-key")
                        Text("Private key").tag("private-key")
                        Text("Environment value").tag("env-value")
                        Text("Other").tag("unknown")
                    }
                }
                VStack(alignment: .leading, spacing: 6) {
                    Text(edit.kind == .firewall ? "Regular expression" : "Paths, one per line")
                    TextEditor(text: $edit.expression)
                        .font(.body.monospaced())
                        .frame(height: 110)
                        .border(Color.secondary.opacity(0.3))
                        .accessibilityLabel(edit.kind == .firewall ? "Regular expression" : "Guarded paths")
                    Text(edit.kind == .firewall ? "Uses Go regular expression syntax. Enter a pattern, never a secret value."
                         : "Use a file path or glob, such as ~/.ssh/id_* or ~/private/**.")
                        .font(.caption).foregroundStyle(.secondary)
                }
                if edit.kind == .guardPath {
                    Toggle("Contains secrets", isOn: $edit.readSensitive)
                }
            }
            if let error {
                Text(error).foregroundStyle(Color.bad).font(.callout).fixedSize(horizontal: false, vertical: true)
            }
            HStack {
                if settings.saving { ProgressView().controlSize(.small) }
                Spacer()
                Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
                Button("Save") {
                    Task {
                        do { try await settings.save(edit); didSave(); dismiss() }
                        catch { self.error = error.localizedDescription }
                    }
                }
                .keyboardShortcut(.defaultAction)
                .disabled(edit.ruleID.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || edit.expression.isEmpty || settings.saving)
            }
        }
        .padding(24).frame(width: 500)
        .disabled(settings.saving)
    }
}

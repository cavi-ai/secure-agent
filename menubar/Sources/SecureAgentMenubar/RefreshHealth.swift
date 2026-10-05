import Foundation

/// Tracks endpoint freshness independently of the values retained by AppState.
/// A successful endpoint can only recover its own failed section.
@MainActor
final class RefreshHealth {
    enum Section: String {
        case status = "Status"
        case findings = "Findings"
        case incidents = "Incidents"
        case posture = "Posture"
        case guardRules = "Guard rules"
        case notifications = "Notifications"
        case resources = "Resources"
        case guardDecisions = "Guard decisions"
    }

    private(set) var staleSections: Set<Section> = []

    var warning: String? {
        guard !staleSections.isEmpty else { return nil }
        let labels = staleSections.map(\.rawValue).sorted().joined(separator: ", ")
        return "Could not refresh: \(labels). Showing last available data; freshness is unknown."
    }

    func refresh<T>(_ section: Section, _ operation: @MainActor () async throws -> T) async throws -> T {
        do {
            let value = try await operation()
            staleSections.remove(section)
            return value
        } catch {
            staleSections.insert(section)
            throw error
        }
    }
}

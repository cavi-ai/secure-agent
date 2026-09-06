import SwiftUI

/// Incident detail sheet: renders the daemon-generated rotation advisory /
/// remediation checklist (the `/incidents?format=markdown` report) so the user
/// can act on a leak without leaving the menu bar.
@MainActor
struct IncidentDetailView: View {
    let incident: IncidentReportModel
    @State private var markdown: String?
    @State private var loadError: String?
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Image(systemName: "cross.case.fill").foregroundStyle(.red)
                Text("\(incident.rule) — \(incident.agent)")
                    .font(.system(size: 14, weight: .bold))
                Spacer()
                Text(incident.risk.uppercased())
                    .font(.system(size: 10, weight: .bold))
                    .foregroundStyle(.red)
                    .padding(.horizontal, 8).padding(.vertical, 4)
                    .background(Color.red.opacity(0.12)).clipShape(Capsule())
                Button("Done") { dismiss() }
                    .keyboardShortcut(.cancelAction)
            }
            .padding(14)
            Divider()
            Group {
                if let markdown {
                    ScrollView {
                        Text(markdown)
                            .font(.system(size: 11, design: .monospaced))
                            .textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(14)
                    }
                } else if let loadError {
                    VStack(spacing: 8) {
                        Image(systemName: "exclamationmark.triangle").font(.title2)
                        Text(loadError).font(.system(size: 11)).foregroundStyle(.secondary)
                            .multilineTextAlignment(.center)
                    }
                    .frame(maxWidth: .infinity, maxHeight: .infinity).padding(20)
                } else {
                    ProgressView("Loading remediation checklist…")
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                }
            }
        }
        .frame(width: 480, height: 420)
        .task {
            do {
                markdown = try await DaemonClient().fetchIncidentMarkdown(id: incident.id)
            } catch {
                loadError = "Could not load the incident report: \(error.localizedDescription)"
            }
        }
    }
}

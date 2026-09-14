import SwiftUI

/// The activity kinds surfaced in a process transcript, mapped from the
/// daemon's event kinds (daemon/internal/event/event.go). Numbers match the
/// Go iota order; unknown kinds render with a generic glyph rather than
/// vanishing — an invisible event reads as "nothing happened".
@MainActor
let eventKindInfo: (Int) -> (icon: String, color: Color, label: String) = { kind in
    switch kind {
    case 0: return ("doc", .brand, "read")            // file open
    case 1: return ("square.and.pencil", .warn, "write")
    case 2: return ("trash", .bad, "delete")          // file delete
    case 3: return ("terminal", .brand, "exec")       // spawned a process
    case 4: return ("hand.raised", .warn, "perms")    // TCC modify
    case 5: return ("network", .ok, "connect")
    case 6: return ("network", Color.secondary, "closed")
    case 7: return ("key.viewfinder", .bad, "secret") // pattern hit in transcript
    case 8: return ("wrench.and.screwdriver", .brand, "tool")
    case 9: return ("shield.lefthalf.filled", .warn, "inspect")
    case 10: return ("lock.shield", .warn, "prompt")
    case 11: return ("lock.open", .ok, "resolved")
    default: return ("questionmark.circle", Color.secondary, "event")
    }
}

/// Compact relative time for transcript rows: "14s", "3m", "2h", "5d".
/// Absolute under the cursor via help — a transcript should read like a log,
/// not a wall of RFC3339.
func relativeTime(_ iso: String, now: Date = Date()) -> String? {
    guard let t = EventTime.parse(iso) else { return nil }
    let d = Int(now.timeIntervalSince(t))
    if d < 0 { return "now" }
    if d < 60 { return "\(d)s" }
    if d < 3600 { return "\(d / 60)m" }
    if d < 86400 { return "\(d / 3600)h" }
    return "\(d / 86400)d"
}

func absoluteTime(_ iso: String) -> String {
    guard let t = EventTime.parse(iso) else { return iso }
    return EventTime.display.string(from: t)
}

/// One shared parser: the daemon emits RFC3339Nano; parsing cost is paid once
/// per row, not per style. The formatters are immutable after config, so a
/// shared nonisolated instance is safe (the classic formatter caveat is
/// mutation, and nothing mutates these).
enum EventTime {
    nonisolated(unsafe) static let rfc3339: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return f
    }()

    /// The daemon also emits plain RFC3339 (no fractional seconds) in some
    /// paths; try both before giving up.
    nonisolated(unsafe) static let rfc3339NoFrac: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime]
        return f
    }()

    nonisolated(unsafe) static let display: DateFormatter = {
        let f = DateFormatter()
        f.dateStyle = .none
        f.timeStyle = .medium
        return f
    }()

    static func parse(_ iso: String) -> Date? {
        rfc3339.date(from: iso) ?? rfc3339NoFrac.date(from: iso)
    }
}

/// Memory formatting shared with the agents list.
enum ByteCount {
    static func short(_ bytes: UInt64?) -> String? {
        guard let bytes, bytes > 0 else { return nil }
        return ByteCountFormatter.string(fromByteCount: Int64(bytes), countStyle: .memory)
    }
}

/// Process detail sheet: the "what is this thing actually doing" answer.
/// Shows identity (what, where, when started, memory), its family position
/// (who spawned it, its children), and a live transcript of its attributed
/// events — the disambiguator when 26 "claude" rows are on screen.
@MainActor
struct ProcessDetailSheet: View {
    let agent: AgentSummaryModel
    let state: AppState
    @State private var events: [EventModel] = []
    @State private var loadError: String?
    @State private var isLive = true
    /// Newest-first in the store; render oldest-first so the transcript reads
    /// top-to-bottom like a terminal.
    @State private var autoScrollToLatest = false
    @Environment(\.dismiss) private var dismiss

    private var children: [AgentSummaryModel] {
        state.agentRoots + state.childAgents
            .filter { $0.ppid == agent.pid }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
            Divider()
            if loadError != nil {
                errorView
            } else {
                transcript
            }
            Divider()
            footer
        }
        .frame(width: 520, height: 480)
        .task { await load() }
        // Live tail: every poll tick appends newly-attributed events. Canceled
        // by SwiftUI when the sheet dismisses.
        .task(id: state.eventsRefreshTick) {
            guard isLive else { return }
            await load()
        }
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 10) {
                Image(systemName: "app.connected")
                    .font(.system(size: 18, weight: .semibold))
                    .foregroundStyle(.brand)
                    .frame(width: 34, height: 34)
                    .background(Color.brand.opacity(0.12))
                    .clipShape(RoundedRectangle(cornerRadius: 8))
                VStack(alignment: .leading, spacing: 1) {
                    Text("\(agent.name) · PID \(agent.pid)")
                        .font(.system(size: 14, weight: .bold))
                    if let cwd = agent.cwd, !cwd.isEmpty {
                        Text(cwd)
                            .font(.system(size: 10, design: .monospaced))
                            .foregroundStyle(.tertiary)
                            .lineLimit(1)
                            .truncationMode(.head)
                            .help(cwd)
                    }
                }
                Spacer()
                Button("Done") { dismiss() }
                    .keyboardShortcut(.cancelAction)
            }
            HStack(spacing: 14) {
                if let mem = ByteCount.short(agent.rssBytes) {
                    Label(mem, systemImage: "memorychip")
                }
                if let started = relativeTime(agent.startedAt ?? "") {
                    Label("up \(started)", systemImage: "clock")
                }
                if let seen = relativeTime(agent.lastSeenAt ?? "") {
                    Label("active \(seen) ago", systemImage: "bolt")
                        .foregroundStyle(isActive ? Color.ok : Color.secondary)
                }
                if agent.rootPid == nil || agent.rootPid == agent.pid {
                    Label("session root", systemImage: "flag.checkered")
                }
            }
            .font(.system(size: 11))
            .foregroundStyle(.secondary)
        }
        .padding(14)
    }

    /// Activity within the last 30s — "last seen 2s ago" vs "14m ago" is the
    /// live/stale read the user is really asking for.
    private var isActive: Bool {
        guard let iso = agent.lastSeenAt,
              let t = EventTime.parse(iso) else { return false }
        return Date().timeIntervalSince(t) < 30
    }

    private var transcript: some View {
        Group {
            if events.isEmpty {
                VStack(spacing: 8) {
                    Image(systemName: "text.justify.leading")
                        .font(.title3)
                        .foregroundStyle(.quaternary)
                    Text("No attributed activity yet")
                        .font(.system(size: 12))
                        .foregroundStyle(.tertiary)
                    Text("File opens, connections, spawns, and tool calls this process makes appear here as they happen.")
                        .font(.system(size: 11))
                        .foregroundStyle(.tertiary)
                        .multilineTextAlignment(.center)
                        .frame(maxWidth: 320)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                ScrollViewReader { proxy in
                    ScrollView {
                        LazyVStack(alignment: .leading, spacing: 0) {
                            ForEach(events) { ev in
                                transcriptRow(ev)
                            }
                            Color.clear.frame(height: 1).id("bottom")
                        }
                        .padding(.vertical, 6)
                    }
                    .onChange(of: events.count) { _, _ in
                        guard autoScrollToLatest else { return }
                        withAnimation(.easeOut(duration: 0.2)) {
                            proxy.scrollTo("bottom", anchor: .bottom)
                        }
                    }
                }
            }
        }
    }

    private func transcriptRow(_ ev: EventModel) -> some View {
        let info = eventKindInfo(ev.kind)
        return HStack(alignment: .top, spacing: 8) {
            Text(relativeTime(ev.ts) ?? "·")
                .font(.system(size: 10, weight: .medium, design: .monospaced))
                .foregroundStyle(.secondary)
                .frame(width: 34, alignment: .trailing)
            Image(systemName: info.icon)
                .font(.system(size: 10))
                .foregroundStyle(info.color)
                .frame(width: 14)
            VStack(alignment: .leading, spacing: 1) {
                HStack(spacing: 6) {
                    Text(info.label.uppercased())
                        .font(.system(size: 9, weight: .bold))
                        .kerning(0.5)
                        .foregroundStyle(info.color)
                    if let sid = ev.sessionId, !sid.isEmpty {
                        Text("session \(sid.prefix(8))")
                            .font(.system(size: 9, design: .monospaced))
                            .foregroundStyle(.quaternary)
                    }
                }
                if let p = ev.path, !p.isEmpty {
                    Text(p)
                        .font(.system(size: 10, design: .monospaced))
                        .foregroundStyle(.primary)
                        .lineLimit(1)
                        .truncationMode(.head)
                        .help(p)
                }
                if let host = ev.remoteHost, !host.isEmpty {
                    Text("→ \(host)\(ev.remotePort.map { ":\($0)" } ?? "")")
                        .font(.system(size: 10, design: .monospaced))
                        .foregroundStyle(.secondary)
                }
                if let d = ev.detail, !d.isEmpty {
                    Text(d)
                        .font(.system(size: 10))
                        .foregroundStyle(.tertiary)
                        .lineLimit(2)
                }
            }
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 5)
        .background(alignment: .leading) {
            // Left rail makes parent/child attribution scannable.
            Rectangle().fill(info.color.opacity(0.5)).frame(width: 2)
                .padding(.leading, 8)
        }
    }

    private var footer: some View {
        HStack(spacing: 8) {
            Toggle(isOn: $isLive) {
                Label(isLive ? "Live" : "Paused",
                      systemImage: isLive ? "dot.radiowaves.left.and.right" : "pause.circle")
                    .font(.system(size: 11, weight: .medium))
            }
            .toggleStyle(.switch)
            .controlSize(.mini)
            Spacer()
            Text("\(events.count) event\(events.count == 1 ? "" : "s")")
                .font(.system(size: 10))
                .foregroundStyle(.tertiary)
            Button { state.kill(pid: agent.pid) ; dismiss() } label: {
                Label("Kill", systemImage: "power")
                    .font(.system(size: 11, weight: .semibold))
            }
            .buttonStyle(.bordered)
            .controlSize(.small)
            .tint(.bad)
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
    }

    private func load() async {
        do {
            events = try await state.uiClient.fetchEventsFor(pid: agent.pid, limit: 300)
                .sorted { $0.ts < $1.ts }
            loadError = nil
            autoScrollToLatest = true
        } catch {
            loadError = "Could not load the transcript: \(error.localizedDescription)"
        }
    }
}

/// A process transcript sheet's error state is inline (banner style) —
/// consistent with IncidentDetailView.
extension ProcessDetailSheet {
    var errorView: some View {
        VStack(spacing: 8) {
            Image(systemName: "exclamationmark.triangle")
                .font(.title3)
                .foregroundStyle(Color.warn)
            Text(loadError ?? "")
                .font(.system(size: 11))
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}
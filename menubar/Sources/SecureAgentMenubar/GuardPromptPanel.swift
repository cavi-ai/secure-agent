import AppKit
import SwiftUI

/// How the guard prompt was answered. `withdrawn`: the request left the
/// pending list while the prompt was up, so nothing is submitted.
enum GuardPromptChoice: Equatable {
    case allowOnce
    case allow(GuardScopeChoice)
    case deny
    case inspect
    case withdrawn
}

/// What the prompt shows: the request, why inspection cannot open (nil when
/// it can), and the duration selected when it opens.
struct GuardPromptContent {
    let pending: GuardPending
    let inspectUnavailableReason: String?
    var selected: GuardScopeChoice? = nil
}

enum GuardPromptDuration: Hashable {
    case once
    case scope(GuardScopeChoice)

    var label: String {
        switch self {
        case .once: return "Once"
        case .scope(let c) where c.kind == "session": return "This session"
        case .scope(let c) where c.kind == "standing": return "Always"
        case .scope(let c): return c.expiry == "7d" ? "7 days" : "24 hours"
        }
    }
}

/// The prompt's state. The first answer wins; later ones are ignored.
@MainActor
final class GuardPromptModel: ObservableObject {
    let content: GuardPromptContent
    @Published var duration: GuardPromptDuration = .once
    /// The permission covers every send of the request's kinds, not its sinks.
    @Published var coversKind = false
    @Published var showsDetails = false
    private(set) var choice: GuardPromptChoice?
    var onChoose: (GuardPromptChoice) -> Void = { _ in }
    var onContentHeight: (CGFloat) -> Void = { _ in }

    init(content: GuardPromptContent) {
        self.content = content
        if let selected = content.selected ?? content.pending.defaultScope,
           let exact = scopes.first(where: { $0.kind == selected.kind && $0.expiry == selected.expiry && !$0.coversKind }),
           selected.coversKind ? kindLabel != nil : true {
            duration = .scope(exact)
            coversKind = selected.coversKind
        }
    }

    private var scopes: [GuardScopeChoice] { content.pending.availableScopes ?? [] }

    var durations: [GuardPromptDuration] {
        [.once] + scopes.filter { $0.kind != "once" && !$0.coversKind }.map { .scope($0) }
    }

    /// "git pushes" when the request offers permissions for its kinds of send.
    var kindLabel: String? {
        scopes.contains(where: \.coversKind) ? GuardSendKind.label(content.pending.categories) : nil
    }

    /// The permission Allow grants; nil for Once.
    var chosenScope: GuardScopeChoice? {
        guard case .scope(let c) = duration else { return nil }
        if coversKind, let kind = scopes.first(where: { $0.kind == c.kind && $0.expiry == c.expiry && $0.coversKind }) { return kind }
        return c
    }

    var allowTitle: String { chosenScope?.label ?? "Allow Once" }

    /// What Allow does with the chosen duration; nothing asks again after it.
    var allowNote: String {
        if let c = chosenScope { return content.pending.grantTerms(scope: c.kind, expiry: c.expiry, category: c.coversKind) ?? c.label }
        return "Allow Once answers only this request."
    }

    /// "Asked 3 times this session about git pushes." once a kind repeats.
    var repeatNote: String? {
        guard let repeats = content.pending.repeats, repeats > 0, let kinds = GuardSendKind.label(content.pending.categories) else { return nil }
        return "Asked \(repeats + 1) times this session about \(kinds)."
    }

    func allow() {
        if let c = chosenScope { choose(.allow(c)) } else { choose(.allowOnce) }
    }

    func deny() { choose(.deny) }

    func inspect() {
        guard content.inspectUnavailableReason == nil else { return }
        choose(.inspect)
    }

    private func choose(_ c: GuardPromptChoice) {
        guard choice == nil else { return }
        choice = c
        onChoose(c)
    }
}

/// The native guard prompt: a floating panel near the top of the screen,
/// awaited until answered or withdrawn. Return and Escape deny. It is not
/// modal: a modal loop started from the main actor would stop the polling
/// and event stream that withdraw it.
@MainActor
final class GuardPromptPanel: NSPanel {
    static let width: CGFloat = 480

    /// The prompt on screen, if any.
    private(set) static weak var shown: GuardPromptPanel?

    let model: GuardPromptModel
    private let host: NSHostingView<GuardPromptView>
    private var answer: CheckedContinuation<GuardPromptChoice, Never>?

    init(content: GuardPromptContent) {
        model = GuardPromptModel(content: content)
        // The window is sized by hand from the content's intrinsic size:
        // hosting min/max constraints loop against the full-size titlebar.
        host = NSHostingView(rootView: GuardPromptView(model: model))
        host.sizingOptions = [.intrinsicContentSize]
        super.init(contentRect: NSRect(x: 0, y: 0, width: Self.width, height: 300),
                   styleMask: [.titled, .fullSizeContentView, .nonactivatingPanel], backing: .buffered, defer: false)
        // Key without activating the app: a menu bar app is often refused
        // activation, and the prompt must still take Return and Escape.
        becomesKeyOnlyIfNeeded = false
        title = AppState.guardPromptHeadline(content.pending)
        titleVisibility = .hidden
        titlebarAppearsTransparent = true
        isMovableByWindowBackground = true
        isReleasedWhenClosed = false
        hidesOnDeactivate = false
        // macOS may refuse to activate this app while the agent's app is in
        // front; the prompt sits above other apps' windows on the front Space.
        level = .modalPanel
        collectionBehavior.formUnion(AppDelegate.popoverSpaces)
        animationBehavior = .alertPanel
        appearance = NSAppearance(named: .darkAqua)
        for button in [NSWindow.ButtonType.closeButton, .miniaturizeButton, .zoomButton] {
            standardWindowButton(button)?.isHidden = true
        }
        model.onChoose = { [weak self] in self?.finish($0) }
        model.onContentHeight = { [weak self] in self?.fit(height: $0) }
        contentView = host
        host.layoutSubtreeIfNeeded()
    }

    /// Follows the content's height, keeping the top edge in place.
    private func fit(height: CGFloat) {
        let size = frameRect(forContentRect: NSRect(x: 0, y: 0, width: Self.width, height: height)).size
        guard abs(size.height - frame.height) > 0.5 else { return }
        var next = frame
        next.origin.y += next.height - size.height
        next.size = size
        setFrame(next, display: true)
    }

    override var canBecomeKey: Bool { true }
    override var canBecomeMain: Bool { true }
    override func cancelOperation(_ sender: Any?) { model.deny() }

    /// The first answer or withdrawal wins.
    private func finish(_ choice: GuardPromptChoice) {
        guard let answer else { return }
        self.answer = nil
        orderOut(nil)
        if Self.shown === self { Self.shown = nil }
        answer.resume(returning: choice)
    }

    /// Closes the prompt without an answer.
    func withdraw() { finish(.withdrawn) }

    static func withdrawShown() { shown?.withdraw() }

    /// Centered horizontally on the screen with the pointer, under the menu bar.
    func placeOnScreen() {
        let mouse = NSEvent.mouseLocation
        guard let screen = NSScreen.screens.first(where: { $0.frame.contains(mouse) }) ?? NSScreen.main else { return }
        let area = screen.visibleFrame
        setFrameOrigin(NSPoint(x: area.midX - frame.width / 2, y: area.maxY - frame.height - area.height * 0.12))
    }

    /// Shows the prompt and returns its answer, or `.withdrawn`.
    static func present(_ content: GuardPromptContent) async -> GuardPromptChoice {
        let panel = GuardPromptPanel(content: content)
        panel.placeOnScreen()
        return await withCheckedContinuation { answer in
            panel.answer = answer
            shown = panel
            panel.makeKeyAndOrderFront(nil)
        }
    }
}

struct GuardPromptView: View {
    @ObservedObject var model: GuardPromptModel

    private var p: GuardPending { model.content.pending }
    private var sends: Bool { p.ruleID == "untrusted-egress" }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
                .padding(.horizontal, 22).padding(.top, 24).padding(.bottom, 18)
            VStack(alignment: .leading, spacing: 10) {
                if let sources = p.untrustedSources {
                    card(title: "Untrusted content it read", color: .warn) {
                        ForEach(Array(sources.enumerated()), id: \.offset) { _, source in
                            HStack(alignment: .firstTextBaseline, spacing: 7) {
                                Circle().fill(Color.warn).frame(width: 5, height: 5).alignmentGuide(.firstTextBaseline) { $0[.bottom] }
                                code(source, lines: 2)
                            }
                        }
                    }
                } else if let why = p.detail, !why.isEmpty {
                    card(title: "Why", color: sends ? .warn : .brand) {
                        Text(why).font(.system(size: 12)).foregroundStyle(.primary.opacity(0.9))
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
                if let advice = p.advisor {
                    card(title: "Advisor", color: ConsoleView.advisorColor(advice.recommendation),
                         symbol: ConsoleView.advisorSymbol(advice.recommendation)) {
                        Text(advice.rationale).font(.system(size: 12)).foregroundStyle(.primary.opacity(0.9))
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
            }
            .padding(.horizontal, 22)
            if model.durations.count > 1 {
                durationRow
                    .padding(.horizontal, 22).padding(.top, 16)
            }
            details
                .padding(.horizontal, 22).padding(.top, 14).padding(.bottom, 16)
            Divider()
            footer
                .padding(.horizontal, 22).padding(.top, 14).padding(.bottom, 16)
        }
        .frame(width: GuardPromptPanel.width)
        .fixedSize(horizontal: false, vertical: true)
        .onGeometryChange(for: CGFloat.self, of: { $0.size.height }) { model.onContentHeight($0) }
        .background(Color.appSurface.opacity(0.84).ignoresSafeArea())
        .background(VisualEffectBackground().ignoresSafeArea())
        .ignoresSafeArea()
        .preferredColorScheme(.dark)
    }

    private var header: some View {
        HStack(alignment: .top, spacing: 16) {
            ZStack(alignment: .bottomTrailing) {
                AgentIdentity.tile(p.agent, size: 60)
                Image(systemName: sends ? "arrow.up.forward.circle.fill" : "lock.shield.fill")
                    .font(.system(size: 22))
                    .symbolRenderingMode(.palette)
                    .foregroundStyle(.white, sends ? Color.warn : Color.brandAction)
                    .background(Circle().fill(Color(nsColor: .windowBackgroundColor)).padding(-2))
                    .offset(x: 7, y: 7)
            }
            .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 6) {
                (Text(p.agent.capitalized).fontWeight(.semibold).foregroundColor(.primary) +
                 Text(sends ? " wants to send data to" : " wants \(p.tool) access to").foregroundColor(.secondary))
                    .font(.system(size: 15))
                Text(p.path)
                    .font(.system(size: 16, weight: .semibold, design: .monospaced))
                    .foregroundStyle(.primary)
                    .lineLimit(2).truncationMode(.middle)
                    .textSelection(.enabled)
                    .help(p.path)
                if sends {
                    Label("after reading untrusted content", systemImage: "exclamationmark.triangle.fill")
                        .font(.system(size: 12, weight: .medium)).foregroundStyle(Color.warn)
                }
                HStack(spacing: 12) {
                    if let ws = p.workspace, !ws.isEmpty {
                        Label((ws as NSString).lastPathComponent, systemImage: "folder").help(ws)
                    }
                    if !sends { Label(p.ruleID, systemImage: "shield.lefthalf.filled").help("Matched rule") }
                }
                .font(.system(size: 11)).foregroundStyle(.secondary).lineLimit(1)
            }
            Spacer(minLength: 0)
        }
    }

    private func sectionLabel(_ text: String) -> some View {
        Text(text.uppercased()).font(.system(size: 10, weight: .semibold)).tracking(0.6)
    }

    private func code(_ text: String, lines: Int) -> some View {
        Text(text)
            .font(.system(size: 12, design: .monospaced)).foregroundStyle(.primary.opacity(0.88))
            .lineLimit(lines).truncationMode(.middle)
            .textSelection(.enabled)
            .help(text)
    }

    private func card(title: String, color: Color, symbol: String? = nil, @ViewBuilder content: () -> some View) -> some View {
        VStack(alignment: .leading, spacing: 7) {
            HStack(spacing: 5) {
                if let symbol { Image(systemName: symbol).font(.system(size: 10, weight: .semibold)) }
                sectionLabel(title)
            }
            .foregroundStyle(color)
            content()
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.horizontal, 12).padding(.vertical, 10)
        .background(color.opacity(0.10), in: RoundedRectangle(cornerRadius: 9, style: .continuous))
        .overlay(alignment: .leading) {
            UnevenRoundedRectangle(topLeadingRadius: 9, bottomLeadingRadius: 9, style: .continuous)
                .fill(color).frame(width: 3)
        }
    }

    private var durationRow: some View {
        VStack(alignment: .leading, spacing: 10) {
            if let note = model.repeatNote {
                Label(note, systemImage: "arrow.triangle.2.circlepath")
                    .font(.system(size: 12, weight: .medium)).foregroundStyle(Color.warn)
            }
            HStack(spacing: 14) {
                sectionLabel("Allow for").foregroundStyle(.secondary)
                Picker("Allow for", selection: $model.duration) {
                    ForEach(model.durations, id: \.self) { Text($0.label).tag($0) }
                }
                .pickerStyle(.segmented)
                .labelsHidden()
            }
            if let kinds = model.kindLabel, model.duration != .once {
                HStack(spacing: 14) {
                    sectionLabel("Covers").foregroundStyle(.secondary)
                    Picker("Covers", selection: $model.coversKind) {
                        Text("This send").tag(false)
                        Text("All \(kinds)").tag(true)
                    }
                    .pickerStyle(.segmented)
                    .labelsHidden()
                }
            }
        }
    }

    private var details: some View {
        DisclosureGroup(isExpanded: $model.showsDetails) {
            Grid(alignment: .leadingFirstTextBaseline, horizontalSpacing: 14, verticalSpacing: 6) {
                ForEach(p.requestFactRows, id: \.label) { row in
                    GridRow {
                        Text(row.label).font(.system(size: 11)).foregroundStyle(.secondary)
                        code(row.label == "Workspace" ? (row.value as NSString).abbreviatingWithTildeInPath : row.value, lines: 1)
                            .font(.system(size: 11, design: .monospaced))
                    }
                }
            }
            .padding(.top, 8)
        } label: {
            sectionLabel("Details").foregroundStyle(.secondary)
        }
    }

    private var footer: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 10) {
                Button("Inspect Session") { model.inspect() }
                    .buttonStyle(PromptButtonStyle(fill: .clear, text: .secondary))
                    .disabled(model.content.inspectUnavailableReason != nil)
                    .help(model.content.inspectUnavailableReason
                          ?? "Opens the session. Inspection leaves the request unanswered; its timeout continues.")
                Spacer()
                Button("Deny") { model.deny() }
                    .buttonStyle(PromptButtonStyle(fill: .bad, text: .white))
                    .keyboardShortcut(.defaultAction)
                Button(model.allowTitle) { model.allow() }
                    .buttonStyle(PromptButtonStyle(fill: .white.opacity(0.12), text: .primary))
            }
            Text(model.allowNote)
                .font(.system(size: 11)).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }
}

/// Filled prompt buttons that keep their color whether or not the app is
/// active: the prompt usually appears over another app.
private struct PromptButtonStyle: ButtonStyle {
    let fill: Color
    let text: Color
    @Environment(\.isEnabled) private var isEnabled

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.system(size: 13, weight: .semibold))
            .foregroundStyle(text)
            .padding(.horizontal, 18)
            .frame(minWidth: 84, minHeight: 30)
            .background(fill, in: RoundedRectangle(cornerRadius: 8, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 8, style: .continuous).strokeBorder(.white.opacity(0.08)))
            .opacity(isEnabled ? (configuration.isPressed ? 0.75 : 1) : 0.4)
            .contentShape(Rectangle())
    }
}

/// Behind-window vibrancy, as on system HUDs.
private struct VisualEffectBackground: NSViewRepresentable {
    func makeNSView(context: Context) -> NSVisualEffectView {
        let view = NSVisualEffectView()
        view.material = .hudWindow
        view.blendingMode = .behindWindow
        view.state = .active
        return view
    }

    func updateNSView(_ view: NSVisualEffectView, context: Context) {}
}

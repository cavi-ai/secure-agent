import AppKit
import SwiftUI

/// First-run setup wizard shown when the daemon isn't installed or reachable.
@MainActor
public final class OnboardingWindowController {
    public static let shared = OnboardingWindowController()

    private var window: NSWindow?

    public func show() {
        if let window {
            window.makeKeyAndOrderFront(nil)
            NSApp.activate(ignoringOtherApps: true)
            return
        }
        let view = OnboardingView(onDone: { [weak self] in self?.close() })
        let hosting = NSHostingController(rootView: view)
        let window = NSWindow(contentViewController: hosting)
        window.title = "Secure Agent Setup"
        window.styleMask = [.titled, .closable]
        window.setContentSize(NSSize(width: 480, height: 560))
        window.center()
        window.isReleasedWhenClosed = false
        self.window = window
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    public func close() {
        window?.close()
        window = nil
    }
}

struct OnboardingView: View {
    @ObservedObject private var setup = SetupManager.shared
    var onDone: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack(spacing: 12) {
                Image(systemName: "shield.fill")
                    .font(.system(size: 40))
                    .foregroundStyle(.indigo)
                VStack(alignment: .leading) {
                    Text("Secure Agent Setup").font(.title2).bold()
                    Text("AI-agent security monitor for macOS")
                        .foregroundStyle(.secondary)
                }
            }

            if !setup.isBundled {
                Label("Drag Secure Agent.app to /Applications and relaunch it to install.",
                      systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
            }

            GroupBox("1. Background Daemon") {
                stepRow(
                    done: setup.isDaemonRunning,
                    installed: setup.isDaemonInstalled,
                    title: setup.isDaemonRunning ? "Daemon running" : "Install and start secure-agentd",
                    buttonTitle: setup.isDaemonInstalled ? "Running" : "Install Daemon",
                    action: { try setup.installDaemon() }
                )
            }

            GroupBox("2. Full Disk Access") {
                VStack(alignment: .leading, spacing: 8) {
                    Text("File monitoring requires Full Disk Access for the daemon. Add secure-agentd in System Settings, then click Recheck.")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                    HStack {
                        Button("Open Privacy Settings") { setup.openFullDiskAccessSettings() }
                        Button("Recheck") { Task { await setup.refreshState() } }
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.vertical, 4)
            }

            GroupBox("3. Harness Hooks") {
                stepRow(
                    done: setup.areHooksInstalled,
                    installed: setup.areHooksInstalled,
                    title: setup.areHooksInstalled ? "Hooks installed (Claude, Cursor, opencode)" : "Install Claude / Cursor / opencode hooks",
                    buttonTitle: setup.areHooksInstalled ? "Installed" : "Install Hooks",
                    action: { try setup.installHooks() }
                )
            }

            GroupBox("4. Extras") {
                HStack {
                    Button("Open at Login") { run { try setup.enableLoginItem() } }
                        .disabled(setup.isLoginItemEnabled)
                    Button("Install CLI Tool") { run { try setup.installCLI() } }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.vertical, 4)
            }

            if let err = setup.lastError {
                Text(err).foregroundStyle(.red).font(.callout)
                    .fixedSize(horizontal: false, vertical: true)
            }

            Spacer()

            HStack {
                Spacer()
                Button("Done") { onDone() }
                    .keyboardShortcut(.defaultAction)
                    .disabled(setup.needsSetup)
            }
        }
        .padding(24)
        .frame(width: 480, height: 560)
        .task { await setup.refreshState() }
    }

    @ViewBuilder
    private func stepRow(done: Bool, installed: Bool, title: String, buttonTitle: String,
                         action: @escaping () throws -> Void) -> some View {
        HStack {
            Image(systemName: done ? "checkmark.circle.fill" : "circle")
                .foregroundStyle(done ? .green : .secondary)
            Text(title).font(.callout)
            Spacer()
            Button(buttonTitle) { run(action) }
                .disabled(installed && done)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.vertical, 4)
    }

    private func run(_ action: () throws -> Void) {
        do {
            try action()
        } catch {
            setup.report(error)
        }
        Task { await setup.refreshState() }
    }
}

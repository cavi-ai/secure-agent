import AppKit
import Foundation

/// Opens agents with a process-scoped proxy environment. No shell profile or
/// system proxy is changed, and existing app instances close gracefully.
@MainActor
enum AgentLauncher {
    enum Target {
        case application(URL)
        case command(URL, [String])
    }

    static func target(for harness: String, home: String,
                       environment: [String: String] = ProcessInfo.processInfo.environment) throws -> Target {
        let bundles = ["cursor": ["com.todesktop.230313mzl4w4u92"], "opencode": ["ai.opencode.desktop"],
                       "antigravity": ["com.google.antigravity", "com.google.antigravity-ide"]]
        if let identifiers = bundles[harness] {
            let preferred = identifiers.sorted {
                !NSRunningApplication.runningApplications(withBundleIdentifier: $0).isEmpty &&
                    NSRunningApplication.runningApplications(withBundleIdentifier: $1).isEmpty
            }
            for bundle in preferred {
                if let app = NSWorkspace.shared.urlForApplication(withBundleIdentifier: bundle) { return .application(app) }
            }
        }
        if harness == "codex", let url = URL(string: "codex://"),
           let app = NSWorkspace.shared.urlForApplication(toOpen: url) { return .application(app) }
        let names = harness == "antigravity" ? ["agy"] : [harness]
        let paths = [home + "/.local/bin", home + "/.openclaw/npm/bin", home + "/.npm-global/bin",
                     "/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", "/bin"] +
            (environment["PATH"] ?? "").split(separator: ":").map(String.init).filter { $0.hasPrefix("/") }
        for directory in paths {
            for name in names {
                let url = URL(fileURLWithPath: directory).appendingPathComponent(name)
                if FileManager.default.isExecutableFile(atPath: url.path) {
                    return .command(url, harness == "openclaw" ? ["gateway", "run"] : [])
                }
            }
        }
        throw failure("Install \(OnboardingView.title(harness)) first.")
    }

    static func launch(_ target: Target, harness: String, home: String,
                       environment: [String: String],
                       runProcess: @Sendable (String, [String]) async -> ProcessRunner.Result = ProcessRunner.run) async throws {
        let routing = try validatedEnvironment(environment)
        switch target {
        case .application(let url):
            if let identifier = Bundle(url: url)?.bundleIdentifier {
                for app in NSRunningApplication.runningApplications(withBundleIdentifier: identifier) {
                    try await terminate(app)
                }
            }
            _ = try await openApplication(at: url, environment: routing)
        case .command(let executable, let arguments):
            let path = try commandFile(executable: executable, arguments: arguments, environment: routing,
                                       harness: harness, home: home)
            let result = await runProcess("/usr/bin/open", ["-a", "Terminal", path.path])
            guard result.status == 0 else { throw failure("Could not open \(OnboardingView.title(harness)).") }
        }
    }

    static func validatedEnvironment(_ environment: [String: String]) throws -> [String: String] {
        let proxyKeys = ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"]
        guard proxyKeys.allSatisfy({ key in
            guard let value = environment[key], let url = URLComponents(string: value) else { return false }
            return url.scheme == "http" && url.host == "127.0.0.1" && (url.port ?? 0) > 0 &&
                url.user == "tunnel" && !(url.password ?? "").isEmpty
        }), environment["NO_PROXY"] == "localhost,127.0.0.1,::1",
            environment["no_proxy"] == environment["NO_PROXY"] else {
            throw failure("Routing is not ready. Restart Secure Agent and retry.")
        }
        return environment.filter { (proxyKeys + ["NO_PROXY", "no_proxy"]).contains($0.key) }
    }

    static func commandFile(executable: URL, arguments: [String], environment: [String: String],
                            harness: String, home: String) throws -> URL {
        let environment = try validatedEnvironment(environment)
        guard SetupManager.knownAgents.contains(where: { $0.name == harness }) else { throw failure("Unknown agent.") }
        let dir = URL(fileURLWithPath: home + "/.config/secure-agent/launchers")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let path = dir.appendingPathComponent(harness + ".command")
        let marker = "# secure-agent-managed-launcher"
        if let previous = try? String(contentsOf: path, encoding: .utf8), !previous.hasPrefix("#!/bin/sh\n" + marker + "\n") {
            throw failure("The agent launcher belongs to another installation.")
        }
        var lines = ["#!/bin/sh", marker, "set -eu"]
        for key in environment.keys.sorted() { lines.append("export \(key)=\(quote(environment[key]!))") }
        lines.append("cd " + quote(home))
        if harness == "openclaw" {
            lines.append("unset OPENCLAW_PROFILE")
            lines.append("export OPENCLAW_STATE_DIR=" + quote(home + "/.openclaw"))
            lines.append("export OPENCLAW_CONFIG_PATH=" + quote(home + "/.openclaw/openclaw.json"))
            lines.append("\(quote(executable.path)) gateway stop")
        }
        lines.append("exec " + ([executable.path] + arguments).map(quote).joined(separator: " "))
        try Data((lines.joined(separator: "\n") + "\n").utf8).write(to: path, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: path.path)
        return path
    }

    static func openApplication(at url: URL, environment: [String: String], arguments: [String] = []) async throws -> NSRunningApplication {
        let configuration = NSWorkspace.OpenConfiguration()
        configuration.environment = environment
        configuration.arguments = arguments
        return try await NSWorkspace.shared.openApplication(at: url, configuration: configuration)
    }

    static func removeManagedFiles(home: String) throws {
        let directory = URL(fileURLWithPath: home + "/.config/secure-agent/launchers")
        for agent in SetupManager.knownAgents {
            let file = directory.appendingPathComponent(agent.name + ".command")
            if let body = try? String(contentsOf: file, encoding: .utf8),
               body.hasPrefix("#!/bin/sh\n# secure-agent-managed-launcher\n") {
                try FileManager.default.removeItem(at: file)
            }
        }
    }

    private static func terminate(_ app: NSRunningApplication) async throws {
        if app.isTerminated { return }
        try await withCheckedThrowingContinuation { continuation in
            let wait = TerminationWait(continuation)
            wait.observation = app.observe(\.isTerminated, options: [.new]) { _, change in
                if change.newValue == true { Task { @MainActor in wait.finish(nil) } }
            }
            guard app.terminate() else { wait.finish(failure("Close the agent and retry.")); return }
            if app.isTerminated { wait.finish(nil); return }
            wait.timeout = Task {
                do { try await Task.sleep(for: .seconds(20)) } catch { return }
                wait.finish(app.isTerminated ? nil : failure("Finish the agent's save dialog, then retry."))
            }
        }
    }

    @MainActor
    private final class TerminationWait {
        var observation: NSKeyValueObservation?
        var timeout: Task<Void, Never>?
        private var continuation: CheckedContinuation<Void, any Error>?
        init(_ continuation: CheckedContinuation<Void, any Error>) { self.continuation = continuation }
        func finish(_ error: Error?) {
            guard let continuation else { return }
            self.continuation = nil
            timeout?.cancel()
            observation = nil
            if let error { continuation.resume(throwing: error) } else { continuation.resume() }
        }
    }

    private static func quote(_ value: String) -> String { "'" + value.replacingOccurrences(of: "'", with: "'\"'\"'") + "'" }
    private static func failure(_ message: String) -> NSError { NSError(domain: "AgentLauncher", code: 1, userInfo: [NSLocalizedDescriptionKey: message]) }
}

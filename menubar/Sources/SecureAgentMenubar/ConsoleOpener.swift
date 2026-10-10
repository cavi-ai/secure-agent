import AppKit

/// Record identity comes from the daemon. A missing durable session ID stays
/// a list handoff; a PID cannot identify the same session across reuse.
enum ConsoleDestination: Equatable {
    case session(String)
    case flag(id: String, sessionID: String?)
    case incident(id: String, sessionID: String?)

    static func session(for agent: AgentSummaryModel) -> ConsoleDestination? {
        guard let id = agent.sessionID, !id.isEmpty else { return nil }
        return .session(id)
    }

    var parameters: [(String, String)] {
        switch self {
        case .session(let id): return [("session", id)]
        case .flag(let id, let session):
            return [("flag", id)] + (session.flatMap { $0.isEmpty ? nil : [("session", $0)] } ?? [])
        case .incident(let id, let session):
            return [("incident", id)] + (session.flatMap { $0.isEmpty ? nil : [("session", $0)] } ?? [])
        }
    }

    var tab: String { parameters.contains { $0.0 == "session" } ? "sessions" : "findings" }
}

/// Focus-or-open for the web console: when the default browser already has a
/// console tab, activate THAT tab instead of spawning a duplicate. "Open
/// console" used to open a fresh tab every click — duplicates that dead-end
/// behind the token strip and pile up across the day. Safari and Chrome are
/// handled via AppleScript; every other browser (and every script failure —
/// Automation consent denied, browser not running) falls back to a plain
/// open, because a duplicate tab is bad but no tab is worse.
enum ConsoleOpener {

    /// Credentials and context remain in the fragment, never a request query.
    /// Records cannot choose an origin, port, return URL or credential.
    static func dashboardURL(port: Int, token: String, tab: String? = nil, file: String? = nil,
                             destination: ConsoleDestination? = nil) -> URL? {
        guard (1...65535).contains(port), !token.isEmpty else { return nil }
        var parameters = [("ct", token)]
        if let tab = destination?.tab ?? tab { parameters.append(("tab", tab)) }
        if let file { parameters.append(("file", file)) }
        parameters += destination?.parameters ?? []
        let fragment = parameters.map { "\($0.0)=\(DaemonClient.urlQueryEscape($0.1))" }.joined(separator: "&")
        return URL(string: "http://127.0.0.1:\(port)/dashboard/#\(fragment)")
    }

    /// The browser can request a fresh handoff, never supply a credential,
    /// target port or return URL. Those come only from the local daemon.
    static func isReconnectURL(_ url: URL) -> Bool {
        url.absoluteString == "secure-agent://console/reconnect"
    }

    /// The URL substring identifying a console tab (loopback dashboard).
    static func tabMatch(port: Int) -> String { "127.0.0.1:\(port)/dashboard" }

    /// Escapes a string for an AppleScript double-quoted literal.
    static func appleScriptLiteral(_ s: String) -> String {
        s.replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
    }

    /// AppleScript that loads url into a matching tab, activates it and
    /// returns "focused", or returns "none" when no tab matches. Loading the
    /// URL hands the focused tab the fresh console token (#ct=), so a tab
    /// whose session ended recovers. Pure builder — unit-tested; nil for
    /// browsers without a tab model we speak.
    static func focusScript(browserBundleID: String, match: String, url: String) -> String? {
        let target = appleScriptLiteral(url)
        switch browserBundleID {
        case "com.apple.Safari":
            return """
            tell application "Safari"
                repeat with w in windows
                    repeat with t in tabs of w
                        if URL of t contains "\(match)" then
                            set URL of t to "\(target)"
                            set current tab of w to t
                            set index of w to 1
                            activate
                            return "focused"
                        end if
                    end repeat
                end repeat
            end tell
            return "none"
            """
        case "com.google.Chrome":
            return """
            tell application "Google Chrome"
                repeat with w in windows
                    repeat with i from 1 to (count of tabs of w)
                        if URL of (tab i of w) contains "\(match)" then
                            set URL of (tab i of w) to "\(target)"
                            set active tab index of w to i
                            set index of w to 1
                            activate
                            return "focused"
                        end if
                    end repeat
                end repeat
            end tell
            return "none"
            """
        default:
            return nil
        }
    }

    /// Open url, focusing an existing console tab when the default browser
    /// cooperates. NSAppleScript blocks while the browser answers, so this
    /// always runs off the main thread; the plain-open fallback hops back.
    static func openOrFocus(url: URL, match: String) {
        DispatchQueue.global(qos: .userInitiated).async {
            var focused = false
            if let browserURL = NSWorkspace.shared.urlForApplication(toOpen: url),
               let bundleID = Bundle(url: browserURL)?.bundleIdentifier,
               let source = focusScript(browserBundleID: bundleID, match: match, url: url.absoluteString),
               let script = NSAppleScript(source: source) {
                var err: NSDictionary?
                let result = script.executeAndReturnError(&err)
                focused = err == nil && result.stringValue == "focused"
            }
            if !focused {
                DispatchQueue.main.async { NSWorkspace.shared.open(url) }
            }
        }
    }
}

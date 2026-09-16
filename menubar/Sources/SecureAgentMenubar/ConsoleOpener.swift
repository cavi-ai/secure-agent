import AppKit

/// Focus-or-open for the web console: when the default browser already has a
/// console tab, activate THAT tab instead of spawning a duplicate. "Open
/// console" used to open a fresh tab every click — duplicates that dead-end
/// behind the token strip and pile up across the day. Safari and Chrome are
/// handled via AppleScript; every other browser (and every script failure —
/// Automation consent denied, browser not running) falls back to a plain
/// open, because a duplicate tab is bad but no tab is worse.
enum ConsoleOpener {

    /// The URL substring identifying a console tab (loopback dashboard).
    static func tabMatch(port: Int) -> String { "127.0.0.1:\(port)/dashboard" }

    /// AppleScript that activates a matching tab and returns "focused", or
    /// returns "none" when no tab matches. Pure builder — unit-tested; nil
    /// for browsers without a tab model we speak.
    static func focusScript(browserBundleID: String, match: String) -> String? {
        switch browserBundleID {
        case "com.apple.Safari":
            return """
            tell application "Safari"
                repeat with w in windows
                    repeat with t in tabs of w
                        if URL of t contains "\(match)" then
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
               let source = focusScript(browserBundleID: bundleID, match: match),
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

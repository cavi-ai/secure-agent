import AppKit
import CryptoKit
import Foundation

/// In-app updates, two channels:
///   - Stable: the latest GitHub release DMG, SHA-256-verified against the
///     release's checksums.txt before it is mounted.
///   - Nightly: builds from origin/main of a local git checkout
///     (packaging/update_nightly.sh) — developer-grade; requires a checkout.
@MainActor
public final class UpdateManager: ObservableObject {
    public static let shared = UpdateManager()

    public enum Channel: String, CaseIterable, Sendable {
        case stable, nightly
        public var title: String { self == .stable ? "Stable (releases)" : "Nightly (main)" }
    }

    public enum State: Equatable {
        case idle
        case checking
        case upToDate(String)      // message
        case available(String)     // version available
        case downloading
        case installing
        case nightlyRunning
        case error(String)
    }

    @Published public var channel: Channel {
        didSet { UserDefaults.standard.set(channel.rawValue, forKey: "updateChannel") }
    }
    @Published public private(set) var state: State = .idle
    /// Latest successfully-checked remote version (for the Apply button).
    @Published public private(set) var availableVersion: String?

    private static let releasesURL = URL(string: "https://api.github.com/repos/cavi-ai/secure-agent/releases/latest")!

    private init() {
        let saved = UserDefaults.standard.string(forKey: "updateChannel")
        channel = Channel(rawValue: saved ?? "") ?? .stable
    }

    // MARK: - Version comparison (pure)

    /// True when remoteTag is a NEWER base version than localVersion.
    /// Handles git-describe shapes: "v0.9.0-rc.3-2-gaddc4b4" (post-tag
    /// commits) is NOT older than "v0.9.0-rc.3".
    public nonisolated static func isNewer(remoteTag: String, localVersion: String) -> Bool {
        func parts(_ v: String) -> ([Int], String) {
            var s = v.hasPrefix("v") ? String(v.dropFirst()) : v
            var suffix = ""
            if let i = s.firstIndex(of: "-") {
                suffix = String(s[i...])
                s = String(s[..<i])
            }
            return (s.split(separator: ".").map { Int($0) ?? 0 }, suffix)
        }
        let (rn, rs) = parts(remoteTag)
        let (ln, ls) = parts(localVersion)
        if rn != ln { return !rn.lexicographicallyPrecedes(ln) }
        // Same numeric base.
        if rs == ls { return false }
        if rs.isEmpty { return true }  // remote is a final release, local is a pre-release/describe
        if ls.isEmpty { return false } // local is final, remote is a pre-release
        // Both carry a suffix on the same base (rc tag vs post-tag describe):
        // the installed build is at-or-ahead of the tag it came from.
        return false
    }

    // MARK: - Checksums (pure)

    /// The expected SHA-256 for `filename` from a checksums.txt body
    /// ("<hash>  <path>" lines, path may carry a directory prefix).
    public nonisolated static func expectedSHA256(_ checksums: String, filename: String) -> String? {
        for line in checksums.split(separator: "\n") {
            let cols = line.split(separator: " ", omittingEmptySubsequences: true)
            guard cols.count >= 2, String(cols[0]).count == 64 else { continue }
            let path = String(cols.last!)
            if path == filename || path.hasSuffix("/" + filename) {
                return String(cols[0])
            }
        }
        return nil
    }

    // MARK: - Check

    public func checkNow(currentVersion: String) async {
        state = .checking
        availableVersion = nil
        switch channel {
        case .stable:
            await checkStable(currentVersion: currentVersion)
        case .nightly:
            await checkNightly(currentVersion: currentVersion)
        }
    }

    private struct Release: Decodable {
        let tag_name: String
        let assets: [Asset]
        struct Asset: Decodable { let name: String; let browser_download_url: URL }
    }

    private func checkStable(currentVersion: String) async {
        do {
            var req = URLRequest(url: Self.releasesURL)
            req.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")
            let (data, resp) = try await URLSession.shared.data(for: req)
            guard (resp as? HTTPURLResponse)?.statusCode == 200 else {
                state = .error("release check failed (HTTP \((resp as? HTTPURLResponse)?.statusCode ?? 0))")
                return
            }
            let rel = try JSONDecoder().decode(Release.self, from: data)
            if Self.isNewer(remoteTag: rel.tag_name, localVersion: currentVersion) {
                availableVersion = rel.tag_name
                state = .available(rel.tag_name)
            } else {
                state = .upToDate("on the latest release (\(rel.tag_name))")
            }
        } catch {
            state = .error("release check failed: \(error.localizedDescription)")
        }
    }

    private func checkNightly(currentVersion: String) async {
        guard let repo = Self.discoverRepo() else {
            state = .error("nightly needs a git checkout of secure-agent (stable channel needs none)")
            return
        }
        // Behind-check without moving the tree: fetch, then compare.
        let fetch = Self.run("/usr/bin/git", ["-C", repo, "fetch", "origin", "main"])
        guard fetch.status == 0 else {
            state = .error("git fetch failed: \(fetch.stderr)")
            return
        }
        let behind = Self.run("/usr/bin/git", ["-C", repo, "rev-list", "--count", "HEAD..origin/main"])
        let n = Int(behind.stdout.trimmingCharacters(in: .whitespacesAndNewlines)) ?? 0
        if n > 0 {
            availableVersion = "main+\(n)"
            state = .available("main is \(n) commit\(n == 1 ? "" : "s") ahead")
        } else {
            state = .upToDate("checkout is at origin/main")
        }
    }

    // MARK: - Apply

    public func applyUpdate(currentVersion: String) async {
        switch channel {
        case .stable:
            await applyStable()
        case .nightly:
            await applyNightly()
        }
    }

    private func applyStable() async {
        state = .downloading
        do {
            var req = URLRequest(url: Self.releasesURL)
            req.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")
            let (data, _) = try await URLSession.shared.data(for: req)
            let rel = try JSONDecoder().decode(Release.self, from: data)
            guard let dmg = rel.assets.first(where: { $0.name.hasSuffix(".dmg") }) else {
                state = .error("no DMG asset on the latest release")
                return
            }
            guard let sumsAsset = rel.assets.first(where: { $0.name == "checksums.txt" }) else {
                state = .error("release has no checksums.txt — refusing to install unverified")
                return
            }
            let tmp = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent(dmg.name)
            let (dmgData, _) = try await URLSession.shared.data(from: dmg.browser_download_url)
            try dmgData.write(to: tmp)
            let (sumsData, _) = try await URLSession.shared.data(from: sumsAsset.browser_download_url)
            guard let expected = Self.expectedSHA256(String(decoding: sumsData, as: UTF8.self), filename: dmg.name) else {
                state = .error("checksums.txt has no entry for \(dmg.name)")
                return
            }
            let actual = SHA256.hash(data: dmgData).map { String(format: "%02x", $0) }.joined()
            guard actual == expected else {
                state = .error("SHA-256 mismatch — download corrupted or tampered; not installing")
                return
            }
            state = .installing
            try Self.installDMG(at: tmp)
        } catch {
            state = .error("update failed: \(error.localizedDescription)")
        }
    }

    /// Mount, replace the app bundle in place, detach, relaunch. The bundle is
    /// replaced at its CURRENT location (dist/ for dev installs, /Applications
    /// for real ones) — writing to /Applications may require admin rights,
    /// which is surfaced as an honest error.
    private static func installDMG(at dmg: URL) throws {
        let mount = run("/usr/bin/hdiutil", ["attach", "-nobrowse", "-readonly", dmg.path])
        guard mount.status == 0 else { throw UpdateError.shell("hdiutil attach: \(mount.stderr)") }
        guard let mountPoint = mount.stdout.split(separator: "\n").last?
            .split(separator: "\t").last.map(String.init)?.trimmingCharacters(in: .whitespaces) else {
            throw UpdateError.shell("hdiutil attach: no mount point")
        }
        defer { _ = run("/usr/bin/hdiutil", ["detach", mountPoint]) }
        let src = "\(mountPoint)/Secure Agent.app"
        let dst = Bundle.main.bundleURL.path
        let copy = run("/usr/bin/ditto", [src, dst])
        guard copy.status == 0 else {
            throw UpdateError.shell("install failed (permission?): \(copy.stderr). Install from the DMG manually.")
        }
        // Relaunch: the daemon is a child of the app, so a clean terminate
        // takes it down; the new binary starts fresh.
        _ = run("/usr/bin/open", ["-n", dst])
        NSApp.terminate(nil)
    }

    private func applyNightly() async {
        guard let repo = Self.discoverRepo() else {
            state = .error("nightly needs a git checkout of secure-agent")
            return
        }
        state = .nightlyRunning
        let script = "\(repo)/packaging/update_nightly.sh"
        let r = Self.run("/bin/bash", [script])
        if r.status == 0 {
            state = .upToDate("nightly build installed — the app relaunched itself")
        } else {
            state = .error("nightly build failed: \(r.stderr.isEmpty ? r.stdout : r.stderr)")
        }
    }

    // MARK: - Repo discovery (nightly)

    /// Walk up from the app bundle looking for the checkout (dist/Secure
    /// Agent.app → repo root one level above dist). Nil for /Applications
    /// installs — nightly is honestly unavailable there.
    public nonisolated static func discoverRepo() -> String? {
        discoverRepo(from: Bundle.main.bundleURL)
    }

    /// The walk, injectable for tests (Bundle.main in a test host isn't the
    /// app bundle).
    nonisolated static func discoverRepo(from startURL: URL) -> String? {
        var url = startURL
        for _ in 0..<8 {
            url = url.deletingLastPathComponent()
            let candidate = url.path
            var isDir: ObjCBool = false
            if FileManager.default.fileExists(atPath: "\(candidate)/.git", isDirectory: &isDir),
               isDir.boolValue,
               FileManager.default.fileExists(atPath: "\(candidate)/packaging/update_nightly.sh") {
                return candidate
            }
        }
        return nil
    }

    // MARK: - Process helper

    enum UpdateError: Error { case shell(String) }

    @discardableResult
    nonisolated static func run(_ bin: String, _ args: [String]) -> (status: Int32, stdout: String, stderr: String) {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: bin)
        p.arguments = args
        let out = Pipe(), err = Pipe()
        p.standardOutput = out
        p.standardError = err
        do {
            try p.run()
            p.waitUntilExit()
        } catch {
            return (-1, "", "\(error.localizedDescription)")
        }
        return (p.terminationStatus,
                String(decoding: out.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self),
                String(decoding: err.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self))
    }
}

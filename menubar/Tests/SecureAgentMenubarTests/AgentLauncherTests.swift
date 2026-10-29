import AppKit
import XCTest
@testable import SecureAgentMenubar

@MainActor
final class AgentLauncherTests: XCTestCase {
    private var environment: [String: String] {
        let proxy = "http://tunnel:fixture-token@127.0.0.1:18443"
        return ["HTTP_PROXY": proxy, "HTTPS_PROXY": proxy, "http_proxy": proxy, "https_proxy": proxy,
                "NO_PROXY": "localhost,127.0.0.1,::1", "no_proxy": "localhost,127.0.0.1,::1"]
    }

    func testRoutingEnvironmentRejectsRemoteOrInspectProxies() throws {
        XCTAssertEqual(try AgentLauncher.validatedEnvironment(environment), environment)
        for proxy in ["http://tunnel:fixture-token@example.com:18443", "http://inspect:fixture-token@127.0.0.1:18443", "http://127.0.0.1:18443"] {
            var invalid = environment
            invalid["HTTPS_PROXY"] = proxy
            XCTAssertThrowsError(try AgentLauncher.validatedEnvironment(invalid))
        }
        var extra = environment
        extra["NODE_EXTRA_CA_CERTS"] = "/unrelated"
        XCTAssertNil(try AgentLauncher.validatedEnvironment(extra)["NODE_EXTRA_CA_CERTS"])
    }

    func testCommandLaunchUsesQuotedArgumentsAndKeepsUserFiles() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("launcher '\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let executable = root.appendingPathComponent("agent.sh")
        try "#!/bin/sh\nprintf '%s\\n' \"$HTTPS_PROXY\" \"$1\"\n".write(to: executable, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: executable.path)
        let argument = "literal ' value; $(false)"
        let command = try AgentLauncher.commandFile(executable: executable, arguments: [argument], environment: environment,
                                                    harness: "hermes", home: root.path)
        let result = await ProcessRunner.run("/usr/bin/env", ["-i", "HOME=" + root.path, "PATH=/usr/bin:/bin", "/bin/sh", command.path])
        XCTAssertEqual(result.status, 0)
        XCTAssertEqual(result.stdout, environment["HTTPS_PROXY"]! + "\n" + argument + "\n")
        let permissions = try FileManager.default.attributesOfItem(atPath: command.path)[.posixPermissions] as? Int
        XCTAssertEqual(permissions, 0o700)
        try "user-owned".write(to: command, atomically: true, encoding: .utf8)
        XCTAssertThrowsError(try AgentLauncher.commandFile(executable: executable, arguments: [], environment: environment,
                                                          harness: "hermes", home: root.path))
        XCTAssertEqual(try String(contentsOf: command, encoding: .utf8), "user-owned")
        let managed = try AgentLauncher.commandFile(executable: executable, arguments: [], environment: environment,
                                                    harness: "codex", home: root.path)
        try AgentLauncher.removeManagedFiles(home: root.path)
        XCTAssertFalse(FileManager.default.fileExists(atPath: managed.path))
        XCTAssertEqual(try String(contentsOf: command, encoding: .utf8), "user-owned")
    }

    func testNativeApplicationReceivesRoutingEnvironment() async throws {
        _ = NSApplication.shared
        NSApp.finishLaunching()
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let app = root.appendingPathComponent("RoutingProbe.app")
        let contents = app.appendingPathComponent("Contents")
        let binaries = contents.appendingPathComponent("MacOS")
        try FileManager.default.createDirectory(at: binaries, withIntermediateDirectories: true)
        let output = root.appendingPathComponent("routing.txt")
        let source = root.appendingPathComponent("main.m")
        try """
        #import <Cocoa/Cocoa.h>
        #include <unistd.h>
        @interface RoutingProbeDelegate : NSObject <NSApplicationDelegate>
        @end
        @implementation RoutingProbeDelegate
        - (void)applicationDidFinishLaunching:(NSNotification *)notification {
            NSString *proxy = NSProcessInfo.processInfo.environment[@"HTTPS_PROXY"] ?: @"missing";
            NSString *ready = [NSString stringWithFormat:@"%d\\n%@", getpid(), proxy];
            [ready writeToFile:@"\(output.path)" atomically:YES encoding:NSUTF8StringEncoding error:nil];
        }
        @end
        int main() {
            @autoreleasepool {
                [NSApplication sharedApplication];
                RoutingProbeDelegate *delegate = [RoutingProbeDelegate new];
                NSApp.delegate = delegate;
                [NSApp run];
            }
            return 0;
        }
        """
            .write(to: source, atomically: true, encoding: .utf8)
        let compile = await ProcessRunner.run("/usr/bin/clang", [source.path, "-framework", "Cocoa", "-o", binaries.appendingPathComponent("RoutingProbe").path])
        XCTAssertEqual(compile.status, 0)
        let plist: [String: Any] = ["CFBundleIdentifier": "com.cavi-ai.secure-agent.routing-probe." + UUID().uuidString.lowercased(),
            "CFBundleName": "RoutingProbe", "CFBundleExecutable": "RoutingProbe", "CFBundlePackageType": "APPL", "LSUIElement": true]
        try PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0).write(to: contents.appendingPathComponent("Info.plist"))
        let signed = await ProcessRunner.run("/usr/bin/codesign", ["--force", "--sign", "-", app.path])
        XCTAssertEqual(signed.status, 0)
        let application = try await AgentLauncher.openApplication(at: app, environment: ["HTTPS_PROXY": "before-setup"])
        let identifier = try XCTUnwrap(plist["CFBundleIdentifier"] as? String)
        defer { for instance in NSRunningApplication.runningApplications(withBundleIdentifier: identifier) { instance.forceTerminate() } }
        try await assertProbeReady(output, pid: application.processIdentifier, proxy: "before-setup")
        do {
            try await AgentLauncher.launch(.application(app), harness: "antigravity", home: root.path, environment: environment)
        } catch {
            XCTFail("Graceful restart failed; original terminated: \(application.isTerminated), finished launching: \(application.isFinishedLaunching)")
            throw error
        }
        XCTAssertTrue(application.isTerminated)
        let reopened = try XCTUnwrap(NSRunningApplication.runningApplications(withBundleIdentifier: identifier).first)
        XCTAssertNotEqual(reopened.processIdentifier, application.processIdentifier)
        try await assertProbeReady(output, pid: reopened.processIdentifier, proxy: try XCTUnwrap(environment["HTTPS_PROXY"]))
    }

    /// The probe publishes its PID and environment after Cocoa finishes launching.
    private func assertProbeReady(_ output: URL, pid: pid_t, proxy: String) async throws {
        let expected = "\(pid)\n\(proxy)"
        let ready = XCTNSPredicateExpectation(predicate: NSPredicate { _, _ in
            (try? String(contentsOf: output, encoding: .utf8)) == expected
        }, object: nil)
        await fulfillment(of: [ready], timeout: 20)
        XCTAssertEqual(try String(contentsOf: output, encoding: .utf8), expected)
    }
}

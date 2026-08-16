import AppKit

final class AppDelegate: NSObject, NSApplicationDelegate {
    let installer = Installer()

    func applicationDidFinishLaunching(_ notification: Notification) {
        print("[SecureAgentInstaller] Starting installation...")
        installer.runInstall()
        if let err = installer.installError {
            print("[SecureAgentInstaller] Error: \(err.localizedDescription)")
            exit(1)
        } else {
            print("[SecureAgentInstaller] Installation completed successfully.")
            exit(0)
        }
    }
}

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.run()

import AppKit

/// Runs the production owner in a real AppKit event loop; XCTest's host does
/// not place status windows. No daemon, installed bundle, or user data is used.
@main
@MainActor
struct StatusItemLifecycleRegression {
    static func main() {
        let app = NSApplication.shared
        app.setActivationPolicy(.accessory)
        let owner = StatusItemController {
            let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
            item.button?.image = NSImage(systemSymbolName: "checkmark.shield.fill", accessibilityDescription: "Status lifecycle regression")
            return item
        }
        guard owner.start() else { fatalError("Cannot create status item") }
        Task { @MainActor in
            await requirePlacement(owner)
            for _ in 0..<3 {
                owner.reconcile()
                let removed = owner.item!
                NSStatusBar.system.removeStatusItem(removed)
                owner.reconcile()
                await requirePlacement(owner)
                guard owner.item !== removed else { fail(owner, "Removed item was not replaced") }
                let restored = owner.item
                owner.reconcile()
                guard owner.item === restored else { fail(owner, "Healthy item was unnecessarily replaced") }
            }
            let hidden = owner.item!
            hidden.isVisible = false
            // No state refresh or explicit reconcile: the production timer
            // must recover the control on its own.
            await requirePlacement(owner, timeout: 8)
            guard owner.item !== hidden else { fail(owner, "Timer did not recover hidden item") }
            owner.stop()
            try? await Task.sleep(for: .milliseconds(100))
            guard owner.item == nil else { fail(owner, "Stopped owner resurrected its item") }
            print("Status item lifecycle: repeated native removal, idle recovery, placement, and shutdown passed")
            app.terminate(nil)
        }
        app.run()
    }

    static func requirePlacement(_ owner: StatusItemController, timeout: Int = 3) async {
        let deadline = ContinuousClock.now + .seconds(timeout)
        while ContinuousClock.now < deadline {
            if let item = owner.item, item.isVisible, let window = item.button?.window,
               window.isVisible, NSScreen.screens.contains(where: { screen in
                   let frame = window.frame
                   return frame.width > 0 && frame.height > 0
                       && frame.minX >= screen.frame.minX && frame.maxX <= screen.frame.maxX
                       && frame.minY >= screen.frame.maxY - frame.height - 1
                       && frame.maxY <= screen.frame.maxY + 1
               }) {
                return
            }
            try? await Task.sleep(for: .milliseconds(50))
        }
        fail(owner, "Status item has no visible menu-bar placement")
    }

    static func fail(_ owner: StatusItemController, _ message: String) -> Never {
        owner.stop()
        fputs("\(message)\n", stderr)
        exit(1)
    }
}

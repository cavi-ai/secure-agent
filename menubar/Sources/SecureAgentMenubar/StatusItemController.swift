import AppKit

/// Owns the status item independently of daemon and window lifetimes.
@MainActor
final class StatusItemController {
    private let makeItem: () -> NSStatusItem?
    private(set) var item: NSStatusItem?
    private var timer: Timer?
    private var observers: [NSObjectProtocol] = []
    private var recoveryAttempted = false

    init(makeItem: @escaping () -> NSStatusItem?) {
        self.makeItem = makeItem
    }

    func start() -> Bool {
        if item != nil { return true }
        item = makeItem()
        guard item != nil else { return false }
        let timer = Timer(timeInterval: 5, repeats: true) { [weak self] _ in
            Task { @MainActor [weak self] in self?.reconcile() }
        }
        timer.tolerance = 1
        RunLoop.main.add(timer, forMode: .common)
        self.timer = timer
        for name in [NSApplication.didChangeScreenParametersNotification, NSApplication.didBecomeActiveNotification] {
            observers.append(NotificationCenter.default.addObserver(forName: name, object: nil, queue: .main) { [weak self] _ in
                Task { @MainActor [weak self] in self?.reconcile() }
            })
        }
        return true
    }

    func stop() {
        timer?.invalidate()
        timer = nil
        observers.forEach(NotificationCenter.default.removeObserver)
        observers.removeAll()
        if let item { NSStatusBar.system.removeStatusItem(item) }
        item = nil
        recoveryAttempted = false
    }

    func reconcile() {
        guard let item else { return }
        // Hosted status items use an off-screen AppKit proxy on newer macOS.
        // Its frame cannot establish whether Control Center rendered the icon.
        if item.isVisible, let window = item.button?.window, window.isVisible {
            recoveryAttempted = false
            return
        }
        // AppKit can retain a removed button/window. Recreate once per loss;
        // never spin on a missing window or stop monitoring.
        guard !recoveryAttempted else { return }
        recoveryAttempted = true
        guard let replacement = makeItem() else { return }
        replacement.isVisible = true
        NSStatusBar.system.removeStatusItem(item)
        self.item = replacement
    }
}

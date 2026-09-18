package main

// `secure-agent service install|uninstall|status` — run the daemon headless
// under launchd, independent of the menu bar app.
//
// Why this exists: the daemon normally lives and dies with the menubar app.
// That is correct for a workstation but wrong for a fleet or CI node, where
// nobody is logged into the GUI. A plain launchd service (RunAtLoad, no
// KeepAlive) gives the daemon a GUI-independent lifetime without the
// crash-respawn loop a KeepAlive agent caused — the reason the old launchd
// path was retired. KeepAlive stays off: the daemon's own supervisor already
// restarts collectors, and launchd respawning the whole daemon would fight
// the menubar over the socket.
//
// The service is per-user (LaunchAgent in ~/Library/LaunchAgents). A
// system-wide LaunchDaemon is deliberately not offered here: it needs root,
// and the daemon's socket/state paths are owner-scoped.

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// serviceLabel is DISTINCT from the menubar's legacy label
// (com.cavi-ai.secure-agentd): installing the service must not collide with
// the app's own daemon bookkeeping, and `migrateLegacyLaunchAgent` in the app
// removes the legacy one precisely because it looped.
const serviceLabel = "com.cavi-ai.secure-agent.headless"

func handleService(args []string) {
	if len(args) < 1 {
		fmt.Println("Usage: secure-agent service <install|uninstall|status>")
		os.Exit(1)
	}
	switch args[0] {
	case "install":
		serviceInstall(args[1:])
	case "uninstall":
		serviceUninstall()
	case "status":
		serviceStatus()
	default:
		fmt.Printf("Unknown service subcommand: %s\n\nUsage: secure-agent service <install|uninstall|status>\n", args[0])
		os.Exit(1)
	}
}

// serviceInstall writes the plist and bootstraps the agent. It takes the
// daemon binary path either from argv or by resolving the running CLI's
// sibling (they ship together in the app bundle's Helpers dir).
func serviceInstall(args []string) {
	daemonPath := ""
	if len(args) > 0 {
		daemonPath = args[0]
	}
	if daemonPath == "" {
		daemonPath = defaultDaemonPath()
	}
	if daemonPath == "" {
		fmt.Println("service install: could not locate the secure-agentd binary — pass its path: secure-agent service install /path/to/secure-agentd")
		os.Exit(1)
	}
	if fi, err := os.Stat(daemonPath); err != nil || fi.IsDir() {
		fmt.Printf("service install: %s is not an executable file\n", daemonPath)
		os.Exit(1)
	}

	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Printf("service install: %v\n", err)
		os.Exit(1)
	}
	dir := filepath.Join(home, "Library", "LaunchAgents")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		fmt.Printf("service install: %v\n", err)
		os.Exit(1)
	}
	plistPath := filepath.Join(dir, serviceLabel+".plist")

	logDir := filepath.Join(home, "Library", "Logs", "secure-agent")
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		fmt.Printf("service install: %v\n", err)
		os.Exit(1)
	}

	plist := servicePlistXML(daemonPath, home, logDir)
	if err := os.WriteFile(plistPath, []byte(plist), 0o644); err != nil {
		fmt.Printf("service install: writing plist: %v\n", err)
		os.Exit(1)
	}

	// Reload idempotently: bootout first (ignore "not loaded"), then bootstrap.
	uid := os.Getuid()
	_ = runQuiet("/bin/launchctl", "bootout", fmt.Sprintf("gui/%d/%s", uid, serviceLabel))
	if err := runQuiet("/bin/launchctl", "bootstrap", fmt.Sprintf("gui/%d", uid), plistPath); err != nil {
		fmt.Printf("service install: launchctl bootstrap failed: %v\n", err)
		fmt.Println("The plist was written; inspect it and retry: " + plistPath)
		os.Exit(1)
	}
	fmt.Printf("Headless service installed: %s\n", plistPath)
	fmt.Printf("Logs: %s\n", logDir)
	fmt.Println("The daemon now starts at login and survives the menu bar app quitting.")
	fmt.Println("Note: run EITHER the menu bar app OR the service — two daemons would contend for the same socket.")
}

func serviceUninstall() {
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Printf("service uninstall: %v\n", err)
		os.Exit(1)
	}
	plistPath := filepath.Join(home, "Library", "LaunchAgents", serviceLabel+".plist")
	uid := os.Getuid()
	_ = runQuiet("/bin/launchctl", "bootout", fmt.Sprintf("gui/%d/%s", uid, serviceLabel))
	if err := os.Remove(plistPath); err != nil && !os.IsNotExist(err) {
		fmt.Printf("service uninstall: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Headless service removed.")
}

func serviceStatus() {
	home, _ := os.UserHomeDir()
	plistPath := filepath.Join(home, "Library", "LaunchAgents", serviceLabel+".plist")
	if _, err := os.Stat(plistPath); err != nil {
		fmt.Println("Headless service: not installed")
		return
	}
	uid := os.Getuid()
	out, err := exec.Command("/bin/launchctl", "print", fmt.Sprintf("gui/%d/%s", uid, serviceLabel)).CombinedOutput()
	if err != nil {
		fmt.Printf("Headless service: plist present, not loaded (%s)\n", plistPath)
		return
	}
	state := "loaded"
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "state =") {
			state = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "state ="))
			break
		}
	}
	fmt.Printf("Headless service: %s (%s)\n", state, plistPath)
}

// servicePlistXML is the launchd definition: RunAtLoad, NO KeepAlive. The
// daemon's own supervisor restarts individual collectors; launchd respawning
// the whole process would fight a running menubar app for the socket, which
// is exactly the loop that got the old agent retired.
func servicePlistXML(daemonPath, home, logDir string) string {
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
    <key>Label</key><string>%s</string>
    <key>ProgramArguments</key><array>
        <string>%s</string>
    </array>
    <key>RunAtLoad</key><true/>
    <key>KeepAlive</key><false/>
    <key>ProcessType</key><string>Background</string>
    <key>EnvironmentVariables</key><dict>
        <key>HOME</key><string>%s</string>
    </dict>
    <key>StandardOutPath</key><string>%s/secure-agentd.log</string>
    <key>StandardErrorPath</key><string>%s/secure-agentd.err.log</string>
</dict></plist>
`, serviceLabel, daemonPath, home, logDir, logDir)
}

// defaultDaemonPath resolves the daemon next to this CLI (the app bundle ships
// them in the same Helpers dir) or on PATH.
func defaultDaemonPath() string {
	if exe, err := os.Executable(); err == nil {
		sibling := filepath.Join(filepath.Dir(exe), "secure-agentd")
		if fi, err := os.Stat(sibling); err == nil && !fi.IsDir() {
			return sibling
		}
	}
	if p, err := exec.LookPath("secure-agentd"); err == nil {
		return p
	}
	return ""
}

func runQuiet(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = nil
	cmd.Stderr = nil
	return cmd.Run()
}

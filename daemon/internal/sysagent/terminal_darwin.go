package sysagent

import "os/exec"

// scriptExt makes Terminal run the script when it opens it.
const scriptExt = ".command"

// openTerminal opens the script in a new Terminal window.
var openTerminal = func(script string) error {
	return exec.Command("open", "-a", "Terminal", script).Run()
}

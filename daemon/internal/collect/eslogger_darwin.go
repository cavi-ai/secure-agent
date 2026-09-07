//go:build darwin

package collect

import "os/exec"

// ESLoggerAvailable reports whether the macOS Endpoint Security logger binary
// is present. (On macOS it always is; the check documents the contract.)
func ESLoggerAvailable() bool {
	_, err := exec.LookPath("eslogger")
	return err == nil
}

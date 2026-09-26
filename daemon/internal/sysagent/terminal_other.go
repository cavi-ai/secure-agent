//go:build !darwin

package sysagent

const scriptExt = ".sh"

// openTerminal is nil off macOS: a terminal dispatch hands the operator the
// script to run.
var openTerminal func(script string) error

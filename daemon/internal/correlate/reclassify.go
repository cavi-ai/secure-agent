package correlate

import (
	"path/filepath"
	"strings"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/sensitive"
)

// ReclassifiedReadReason is stored on the sensitive-read-then-connect flags
// the daemon acknowledges at start because none of their reads counts as a
// secret read any more.
const ReclassifiedReadReason = "reclassified at start: the file read is not a secret read (shell or harness config, a .env template, the macOS trust store, or a keychain file opened for TLS)"

// byteCopyTools read a file only to move its bytes somewhere else. A keychain
// file open by one of them is a copy of the keychain; by anything else it is
// Security.framework evaluating a certificate chain.
var byteCopyTools = map[string]bool{
	"cat": true, "cp": true, "ditto": true, "dd": true, "tar": true, "zip": true,
	"gzip": true, "bzip2": true, "xz": true, "scp": true, "sftp": true, "rsync": true,
	"curl": true, "wget": true, "nc": true, "ncat": true, "base64": true, "xxd": true,
	"od": true, "hexdump": true, "openssl": true, "strings": true, "head": true, "tail": true,
}

func isByteCopyTool(exe string) bool {
	return exe != "" && byteCopyTools[strings.ToLower(filepath.Base(exe))]
}

// seedsReadThenConnect reports whether a sensitive-file read counts as a
// secret read for sensitive-read-then-connect. The macOS trust store never
// does: every TLS client reads it. A keychain file counts only when an agent
// tool read it or a byte-copy tool opened it; the keychain-access rule
// records every keychain open either way.
func seedsReadThenConnect(cat sensitive.Category, kind event.Kind, exe string) bool {
	switch cat {
	case sensitive.CatKeychainSystem:
		return false
	case sensitive.CatKeychain:
		return kind == event.KindPluginAction || isByteCopyTool(exe)
	default:
		return true
	}
}

// StaleReadFlagIDs returns the unacknowledged sensitive-read-then-connect
// flags none of whose reads the current rules count as a secret read: a glob
// the classifier no longer matches (guard rules that protect a file from
// tampering but hold no secret, such as shell rc files and harness settings),
// a .env template, a not_secret_paths directory, the macOS trust store, or a
// keychain file not opened by a byte-copy tool.
func StaleReadFlagIDs(flags []model.Flag, cl sensitive.Classifier) []string {
	var ids []string
	for _, f := range flags {
		if f.Rule != "sensitive-read-then-connect" || f.Acknowledged {
			continue
		}
		reads, secret := 0, false
		for _, ev := range f.Evidence {
			if ev.Kind != "read" {
				continue
			}
			reads++
			if storedReadSeeds(ev, f.Process, cl) {
				secret = true
				break
			}
		}
		if reads > 0 && !secret {
			ids = append(ids, f.ID)
		}
	}
	return ids
}

// storedReadSeeds re-judges one stored read. Evidence from before readers
// were recorded falls back to the flag's own process.
func storedReadSeeds(ev model.EvidenceItem, proc *model.FlagProcess, cl sensitive.Classifier) bool {
	exe := ev.Exe
	if exe == "" && proc != nil {
		exe = proc.Exe
	}
	switch {
	case ev.Label == "":
		return true
	case ev.Rule == "system-trust":
		return false
	case strings.HasPrefix(ev.Rule, "keychain:"):
		return isByteCopyTool(exe)
	case strings.HasPrefix(ev.Rule, "glob:"), strings.HasPrefix(ev.Rule, "path:"), ev.Rule == "env-file":
		m, ok := cl.Match(ev.Label)
		return ok && seedsReadThenConnect(m.Category, event.KindFileOpen, exe)
	default:
		return true
	}
}

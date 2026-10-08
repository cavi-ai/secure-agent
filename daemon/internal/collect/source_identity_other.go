//go:build !darwin && !linux

package collect

import "os"

func sourceIdentity(os.FileInfo) string { return "" }

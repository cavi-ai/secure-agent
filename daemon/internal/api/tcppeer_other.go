//go:build !darwin

package api

import "errors"

// TCPClientPID is macOS-only; elsewhere NoAgent routes are refused on the
// console listener.
func TCPClientPID(string) (int32, error) { return 0, errors.ErrUnsupported }

//go:build !linux

package connpeer

import "errors"

// ClientPID is the /proc lookup; macOS uses api.TCPClientPID instead.
func ClientPID(string) (int32, error) { return 0, errors.ErrUnsupported }

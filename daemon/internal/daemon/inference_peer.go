package daemon

import (
	"errors"
	"github.com/cavi-ai/secure-agent/daemon/internal/api"
	"github.com/cavi-ai/secure-agent/daemon/internal/connpeer"
)

func inferenceClientPID(remote string) (int32, error) {
	pid, err := api.TCPClientPID(remote)
	if errors.Is(err, errors.ErrUnsupported) {
		return connpeer.ClientPID(remote)
	}
	return pid, err
}

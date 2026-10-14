package forwarder

import "github.com/cavi-ai/secure-agent/daemon/hookrun"

// Adapter normalizes one host-observed handler completion before it enters the
// common delivery client. Native results remain transient. The decoder owns
// protocol interpretation; Client owns scope, capture health and delivery.
type Adapter struct {
	*Client
	decoder hookrun.Decoder
}

// NewAdapter accepts the native OpenClaw, Hermes and OpenCode decoders, or the
// shared RecordDecoder for hosts already supplying normalized metadata. Claude
// transcript collection remains independent; this does not install host hooks.
func NewAdapter(config Config, decoder hookrun.Decoder) (*Adapter, error) {
	if decoder == nil {
		return nil, hookrun.ErrInvalidInput
	}
	c, err := New(config)
	if err != nil {
		return nil, err
	}
	return &Adapter{Client: c, decoder: decoder}, nil
}

// Submit preserves host execution IDs for retry. Unrelated messages do not
// change capture health. Invalid messages cannot enter the queue or clear a
// preceding failure. Callbacks must not change hook outcomes on these errors.
func (a *Adapter) Submit(input []byte) (string, error) {
	if len(input) > 1024*1024 {
		return "", a.captureResult(hookrun.ErrInvalidInput)
	}
	return a.submit(input, a.decoder)
}

func (c *Client) submit(input []byte, decoder hookrun.Decoder) (string, error) {
	r, recognized, err := decoder.Decode(input)
	if err != nil {
		return "", c.captureResult(err)
	}
	if !recognized {
		return "", nil
	}
	return r.ID, c.Enqueue(r)
}

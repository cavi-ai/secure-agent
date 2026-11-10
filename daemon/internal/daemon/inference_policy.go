package daemon

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/firewall"
	"github.com/cavi-ai/secure-agent/daemon/internal/inference"
	"github.com/cavi-ai/secure-agent/daemon/internal/proxy"
	"github.com/cavi-ai/secure-agent/daemon/internal/taint"
)

func inferenceRequestPolicy(engine *firewall.Engine, gate *taint.Gate, ask func(context.Context, taint.Verdict) bool, publish func(event.Event), identify func(context.Context, string) (int32, string)) (inference.RequestPolicy, error) {
	if engine == nil || gate == nil {
		return inference.RequestPolicy{}, errors.New("inference gateway security policy unavailable")
	}
	// A loopback endpoint can forward cloud requests. Do not inherit the
	// ordinary proxy's model-host exemptions, or mutate its shared gate.
	inferenceGate := *gate
	inferenceGate.Exempt = nil
	gate = &inferenceGate
	return inference.RequestPolicy{
		Inspect: func(r *http.Request) error {
			inspector := proxy.NewRequestInspector(engine, func(e event.Event) {
				if identify != nil {
					e.PID, e.SessionID = identify(r.Context(), r.RemoteAddr)
				}
				if publish != nil {
					publish(e)
				}
			})
			blocked, _, err := inspector.Inspect(r, r.URL.Host)
			if err != nil {
				return err
			}
			if blocked {
				return errors.New("inference request contains a blocked secret")
			}
			return nil
		},
		CheckEgress: func(r *http.Request) error {
			v := gate.Check(r.Context(), r.RemoteAddr, r.URL.Host)
			if v.Mode == "" {
				return nil
			}
			refused := v.Blocked()
			if v.Asks() {
				refused = ask == nil || !ask(r.Context(), v)
				if !refused {
					return nil
				}
			}
			prefix := "proxy-untrusted-egress-monitored: "
			if refused {
				prefix = "proxy-untrusted-egress: "
			}
			if publish != nil {
				port, _ := strconv.Atoi(r.URL.Port())
				if port == 0 {
					port = 80
					if r.URL.Scheme == "https" {
						port = 443
					}
				}
				publish(event.Event{Kind: event.KindProxyHit, TS: time.Now(), PID: v.PID, SessionID: v.SessionID, RemoteHost: v.Host, RemotePort: port, Detail: prefix + v.Detail})
			}
			if refused {
				return errors.New("inference request refused after untrusted content")
			}
			return nil
		},
	}, nil
}

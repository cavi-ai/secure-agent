package proxy

import (
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/firewall"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

// RequestInspector applies the shared firewall and preserves the original wire
// body for forwarding. Large uploads use the encrypted, unlinked body spool.
// Inspect returns an error when capture or decoding cannot be completed;
// callers choose whether that coverage failure refuses the request.
type RequestInspector struct {
	engine  *firewall.Engine
	publish func(event.Event)
}

func NewRequestInspector(engine *firewall.Engine, publish func(event.Event)) *RequestInspector {
	return &RequestInspector{engine: engine, publish: publish}
}

// CoveragePosture decides whether an inspection error refuses the request.
type CoveragePosture int

const (
	// CoverageRecordAndForward refuses only a blocked finding.
	CoverageRecordAndForward CoveragePosture = iota
	// CoverageRefuse refuses a blocked finding or an inspection error.
	CoverageRefuse
)

// InspectionResult is one RequestInspector.Inspect outcome.
type InspectionResult struct {
	Blocked bool
	Detail  string
	Err     error
}

// Refuses reports whether the request stops under p.
func (r InspectionResult) Refuses(p CoveragePosture) bool {
	switch p {
	case CoverageRecordAndForward:
		return r.Blocked
	case CoverageRefuse:
		return r.Err != nil || r.Blocked
	default:
		var unknown CoveragePosture = p
		panic(fmt.Sprintf("unknown coverage posture %d", unknown))
	}
}

func (ps *RequestInspector) Inspect(r *http.Request, host string) (blocked bool, detail string, inspectionErr error) {
	if ps.engine == nil {
		return false, "", errors.New("firewall unavailable")
	}

	hostOnly := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		hostOnly = h
	}

	headers := make(map[string]string, len(r.Header))
	for name, values := range r.Header {
		headers[name] = strings.Join(values, " ")
	}
	inspection := ps.engine.NewInspection(firewall.Request{
		Host: hostOnly, Query: r.URL.RawQuery,
		AuthHeaderName: "authorization", Headers: headers,
	})
	if r.Body != nil && r.Body != http.NoBody {
		body := ps.captureRequestBody(r.Body, host)
		r.Body = body
		inspectionErr = body.coverageErr
		var scan io.Reader = body.spool.reader()
		if body.coverageErr != nil {
			scan = io.MultiReader(scan, &readError{err: body.coverageErr})
		}
		scan = &budgetReader{Reader: scan, left: bodyInspectionCap}
		encoding := strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Encoding")))
		if encoding == "" {
			var magic [2]byte
			_, _ = io.ReadFull(body.spool.reader(), magic[:])
			if magic == [2]byte{0x1f, 0x8b} {
				encoding = "gzip"
			}
		}
		if encoding == "gzip" {
			gz, err := gzip.NewReader(scan)
			if err != nil {
				ps.publishHit(host, "proxy-inspection-incomplete:body-decode")
				inspectionErr = err
				scan = nil
			} else {
				defer gz.Close()
				scan = &budgetReader{Reader: gz, left: bodyInspectionCap}
			}
		} else if encoding != "" && encoding != "identity" {
			inspectionErr = errors.New("unsupported request content encoding")
			ps.publishHit(host, "proxy-inspection-incomplete:body-decode")
		}
		if scan != nil {
			windowed, err := inspection.ScanBody(scan)
			if err != nil {
				inspectionErr = err
			}
			if errors.Is(err, errInspectionLimit) {
				if body.coverageErr != errInspectionLimit {
					ps.publishHit(host, "proxy-inspection-incomplete:body-limit")
				}
			} else if err != nil && err != body.coverageErr {
				ps.publishHit(host, "proxy-inspection-incomplete:body-decode")
			}
			if windowed {
				ps.publishHit(host, "proxy-inspection-incomplete:body-window")
			}
		}
	}
	dec := inspection.Finish()

	// Publish every leak (including monitor-mode would-blocks) for observability;
	// only actually block when the resolved action says so.
	for _, f := range dec.Findings {
		if f.Verdict.Kind != firewall.VerdictLeak {
			continue
		}
		d := fmt.Sprintf("proxy-secret-leak:%s", f.Hit.RuleID)
		layers := map[firewall.Layer]string{firewall.LayerFingerprint: "fingerprint", firewall.LayerPattern: "pattern", firewall.LayerEntropy: "entropy"}
		fields := map[firewall.Field]string{firewall.FieldAuthHeader: "auth-header", firewall.FieldOtherHeader: "other-header", firewall.FieldQuery: "query", firewall.FieldBody: "body"}
		actions := map[firewall.Action]string{firewall.ActionAllow: "allow", firewall.ActionWouldBlock: "would-block", firewall.ActionBlock: "block"}
		ps.publishProxyHit(host, d, &model.PayloadEvidence{Layer: layers[f.Hit.Layer], Field: fields[f.Ctx.Field], Verdict: "leak", FindingAction: actions[f.Verdict.Action], RequestAction: actions[dec.Action]})
		if detail == "" {
			detail = d
		}
	}

	return dec.Action == firewall.ActionBlock, detail, inspectionErr
}

func (ps *RequestInspector) publishHit(host, detail string) {
	ps.publishProxyHit(host, detail, nil)
}
func (ps *RequestInspector) publishProxyHit(host, detail string, payload *model.PayloadEvidence) {
	publishInspectionHit(ps.publish, host, detail, payload)
}

func publishInspectionHit(publish func(event.Event), host, detail string, payload *model.PayloadEvidence) {
	if publish == nil {
		return
	}
	hostOnly, port := splitTarget(host)
	publish(event.Event{Kind: event.KindProxyHit, TS: time.Now(), RemoteHost: hostOnly, RemotePort: port, Detail: detail, Payload: payload})
}

// ClassifyProxyHit maps a KindProxyHit detail to the finding rule, evidence
// sub, and severity. Prefixes are the ones this package publishes.
func ClassifyProxyHit(detail string) (rule, sub string, severity int) {
	rule = "proxy-payload-inspection"
	sub = "payload inspection"
	severity = 3
	switch {
	case strings.HasPrefix(detail, "proxy-untrusted-egress:"):
		rule, sub = "proxy-untrusted-egress", "untrusted-egress"
	case strings.HasPrefix(detail, "proxy-untrusted-egress-monitored:"):
		rule, sub, severity = "proxy-untrusted-egress-monitored", "untrusted-egress", 2
	case strings.HasPrefix(detail, "proxy-secret-leak"):
		rule = "proxy-secret-leak"
	case strings.HasPrefix(detail, "proxy-prompt-injection"):
		rule = "proxy-prompt-injection"
	case strings.HasPrefix(detail, "proxy-inspection-incomplete:"):
		rule = "proxy-inspection-incomplete"
		severity = 2
	}
	return rule, sub, severity
}

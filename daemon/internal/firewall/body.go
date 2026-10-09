package firewall

import (
	"io"
)

const (
	bodyWindow  = 1 << 20
	bodyOverlap = 64 << 10
)

// Inspection accumulates a single request's findings. Overlapping windows and
// decoded views count each rule once per field and detection layer. It is owned
// by one request goroutine; Finish records the request's statistics once.
type Inspection struct {
	engine   *Engine
	registry *Registry
	det      *Detector
	pol      *Policy
	req      Request
	findings []Finding
	seen     map[inspectionKey]bool
	finished bool
}

type inspectionKey struct {
	rule  string
	field Field
	layer Layer
}

func (e *Engine) NewInspection(req Request) *Inspection {
	det, pol := e.policySnapshot()
	i := &Inspection{engine: e, registry: e.reg.Load(), det: det, pol: pol, req: req, seen: make(map[inspectionKey]bool)}
	// Preserve existing header and query policy, including legitimate vendor auth.
	req.Body = nil
	i.add(inspectWith(req, i.registry, det, pol))
	return i
}

func (i *Inspection) add(dec Decision) {
	for _, f := range dec.Findings {
		key := inspectionKey{f.Hit.RuleID, f.Ctx.Field, f.Hit.Layer}
		if !i.seen[key] {
			i.seen[key] = true
			i.findings = append(i.findings, f)
		}
	}
}

func (i *Inspection) scanBody(data []byte, partial bool) {
	ctx := RequestCtx{Agent: i.req.Agent, Host: i.req.Host, Field: FieldBody}
	// Normalize before both detection layers, so encoded typed patterns receive
	// the same coverage as registered fingerprints.
	for _, view := range Normalize(data) {
		hits := i.registry.matchTokens(view)
		hits = append(hits, i.det.scan(view, partial)...)
		for _, h := range hits {
			// Offsets in decoded windows are not offsets in the wire body.
			h.Spans = nil
			i.add(Decision{Findings: []Finding{{Hit: h, Ctx: ctx, Verdict: i.pol.Classify(h, ctx)}}})
		}
	}
}

// ScanBody scans bounded windows while retaining overlap at token boundaries.
// It never treats a sliced token as a complete registered secret. Windowed is
// true when arbitrary patterns spanning more than the overlap may be missed;
// callers must report that bounded coverage rather than claim a full scan.
func (i *Inspection) ScanBody(r io.Reader) (windowed bool, err error) {
	buf := make([]byte, bodyWindow)
	used := 0
	skipping := false
	emptyReads := 0
	for {
		n, readErr := r.Read(buf[used:])
		used += n
		if n == 0 && readErr == nil {
			emptyReads++
			if emptyReads == 100 {
				return windowed, io.ErrNoProgress
			}
		} else {
			emptyReads = 0
		}
		if readErr == nil && used < len(buf) {
			continue
		}
		start := 0
		if skipping {
			for start < used && !isTokenBreak(rune(buf[start])) {
				start++
			}
			if start < used {
				skipping = false
				start++
			}
		}
		if readErr != nil {
			if !skipping {
				end := used
				if readErr != io.EOF {
					for end > start && !isTokenBreak(rune(buf[end-1])) {
						end--
					}
				}
				i.scanBody(buf[start:end], windowed || readErr != io.EOF)
			}
			if readErr == io.EOF {
				return windowed, nil
			}
			return windowed, readErr
		}
		windowed = true
		end := used - 1
		for end >= start && !isTokenBreak(rune(buf[end])) {
			end--
		}
		if end < start {
			// A token exceeds a window. Discard it until its real delimiter;
			// arbitrary slices would fabricate fingerprint or pattern matches.
			used = 0
			skipping = true
			continue
		}
		i.scanBody(buf[start:end+1], true)
		keep := max(start, end+1-bodyOverlap)
		for keep < end && !isTokenBreak(rune(buf[keep])) {
			keep++
		}
		keep++
		used = copy(buf, buf[keep:used])
	}
}

func (i *Inspection) Finish() Decision {
	dec := Decision{Findings: i.findings}
	for _, f := range i.findings {
		if f.Verdict.Action > dec.Action {
			dec.Action = f.Verdict.Action
		}
	}
	if !i.finished {
		i.engine.tally(i.findings)
		i.finished = true
	}
	return dec
}

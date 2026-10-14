// Package opencode adapts observed OpenCode v2 plugin event mutations.
package opencode

import (
	"bytes"
	"encoding/json"
	"errors"
	"unicode/utf8"

	"github.com/cavi-ai/secure-agent/daemon/hookrun"
)

type Decoder struct{}

var _ hookrun.Decoder = Decoder{}

func (Decoder) Decode(line []byte) (hookrun.Record, bool, error) {
	c, r, ok, err := hookrun.DecodeCompletion(line, "opencode")
	if err != nil || !ok {
		return r, ok, err
	}
	if c.Protocol != "opencode-v2" {
		return hookrun.Record{}, true, errors.New("unsupported OpenCode hook protocol")
	}
	if c.State != "completed" {
		return r, true, nil
	}
	switch c.Event {
	case "permission.evaluate":
		if !snapshot(c.Before) || !snapshot(c.Result) {
			return hookrun.Record{}, true, errors.New("OpenCode permission hook requires before and after snapshots")
		}
		var before, after struct {
			Effect  string `json:"effect"`
			Message string `json:"message"`
		}
		if json.Unmarshal(c.Before, &before) != nil || json.Unmarshal(c.Result, &after) != nil || !permissionEffect(before.Effect) || !permissionEffect(after.Effect) {
			return hookrun.Record{}, true, errors.New("invalid OpenCode permission mutation")
		}
		if after.Effect == "deny" && before.Effect != "deny" {
			r.Status = "deny"
			r.Chars = int64(utf8.RuneCountInString(after.Message))
		}
		r.Evidence.CharsKnown = true
	case "session.context", "session.compaction", "session.generate", "session.title":
		if !snapshot(c.Before) || !snapshot(c.Result) {
			return hookrun.Record{}, true, errors.New("OpenCode context hook requires before and after snapshots")
		}
		var before, after struct {
			System *[]struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"system"`
		}
		if json.Unmarshal(c.Before, &before) != nil || json.Unmarshal(c.Result, &after) != nil {
			return hookrun.Record{}, true, errors.New("invalid OpenCode system context mutation")
		}
		if before.System == nil || after.System == nil {
			return hookrun.Record{}, true, errors.New("OpenCode context snapshots require system parts")
		}
		// Match repeated parts by count so unchanged context from the host or
		// an earlier handler is not attributed to this handler.
		old := map[string]int{}
		for _, part := range *before.System {
			if part.Type == "text" {
				old[part.Text]++
			}
		}
		for _, part := range *after.System {
			if part.Type != "text" {
				continue
			}
			if old[part.Text] > 0 {
				old[part.Text]--
				continue
			}
			r.Chars += int64(utf8.RuneCountInString(part.Text))
		}
		if r.Chars > 0 {
			r.Status = "inject"
		}
		r.Evidence.CharsKnown = true
		n := r.Chars
		r.Evidence.ContextChars = &n
	}
	return r, true, nil
}

func snapshot(raw json.RawMessage) bool { b := bytes.TrimSpace(raw); return len(b) > 0 && b[0] == '{' }
func permissionEffect(s string) bool    { return s == "allow" || s == "deny" || s == "ask" }

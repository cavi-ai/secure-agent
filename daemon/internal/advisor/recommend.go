package advisor

import (
	"fmt"
	"slices"
	"strings"
	"unicode"
)

// Recommendation is one advisor model offered for this machine.
type Recommendation struct {
	ID          string `json:"id"`
	Label       string `json:"label"`
	Source      string `json:"source"`             // installed | managed
	Endpoint    string `json:"endpoint,omitempty"` // installed: the server holding it
	Bytes       int64  `json:"bytes,omitempty"`    // 0 = unknown
	Fit         string `json:"fit"`                // fits | tight | too-big | unknown
	Note        string `json:"note"`
	Recommended bool   `json:"recommended,omitempty"`
	rank        int
}

// fit: the model needs its size plus 20 % at runtime; it fits in half the
// machine's memory (agents and apps share the rest), is tight up to three
// quarters, and is too big beyond.
func fit(bytes int64, ram uint64) string {
	if bytes <= 0 || ram == 0 {
		return "unknown"
	}
	need := uint64(bytes) * 6 / 5
	switch {
	case need <= ram/2:
		return "fits"
	case need <= ram*3/4:
		return "tight"
	}
	return "too-big"
}

// notChat marks models that cannot triage: embeddings, OCR, rerankers,
// speech.
var notChat = []string{"embed", "ocr", "rerank", "whisper", "tts"}

func modelTokens(name string) []string {
	return strings.FieldsFunc(strings.ToLower(name), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '.'
	})
}

// catalogRank returns the highest rank among catalog entries whose family
// tokens the model name carries, 0 when none.
func catalogRank(name string) int {
	toks := modelTokens(name)
	best := 0
	for _, c := range Catalog {
		if c.Rank > best && !slices.ContainsFunc(c.Match, func(m string) bool { return !slices.Contains(toks, m) }) {
			best = c.Rank
		}
	}
	return best
}

func gbString(b int64) string { return fmt.Sprintf("%.1f GB", float64(b)/1e9) }

func fitNote(f string) string {
	switch f {
	case "tight":
		return "leaves little memory for agents"
	case "too-big":
		return "needs more memory than this Mac can spare"
	case "unknown":
		return "size unknown"
	}
	return "fits in memory"
}

// Recommend ranks the installed chat models on the discovered servers and the
// catalog for m. The recommendation is the installed catalog-family model
// that fits with the highest rank, else the highest-rank catalog model that
// fits, else the smallest catalog model that is tight. Recommended comes
// first, then fits, tight, unknown, too-big; then rank and size.
func Recommend(m Machine, servers []DiscoveredServer) []Recommendation {
	var recs []Recommendation
	for _, srv := range servers {
		for _, name := range srv.Models {
			lower := strings.ToLower(name)
			if slices.ContainsFunc(notChat, func(s string) bool { return strings.Contains(lower, s) }) {
				continue
			}
			b := srv.Sizes[name]
			f := fit(b, m.RAMBytes)
			note := "installed, no download · " + fitNote(f)
			if b > 0 {
				note = gbString(b) + " · " + note
			}
			recs = append(recs, Recommendation{ID: name, Label: name, Source: "installed", Endpoint: srv.Endpoint,
				Bytes: b, Fit: f, Note: note, rank: catalogRank(name)})
		}
	}
	for _, c := range Catalog {
		f := fit(c.Bytes, m.RAMBytes)
		recs = append(recs, Recommendation{ID: c.ID, Label: c.Label, Source: "managed", Bytes: c.Bytes, Fit: f,
			Note: gbString(c.Bytes) + " download, run by mlx_lm · " + fitNote(f), rank: c.Rank})
	}

	pick := -1
	better := func(i int) bool { return pick < 0 || recs[i].rank > recs[pick].rank }
	for i, r := range recs {
		if r.Source == "installed" && r.rank > 0 && r.Fit == "fits" && better(i) {
			pick = i
		}
	}
	if pick < 0 {
		for i, r := range recs {
			if r.Source == "managed" && r.Fit == "fits" && better(i) {
				pick = i
			}
		}
	}
	if pick < 0 {
		for i, r := range recs {
			if r.Source == "managed" && r.Fit == "tight" && (pick < 0 || r.Bytes < recs[pick].Bytes) {
				pick = i
			}
		}
	}
	if pick >= 0 {
		recs[pick].Recommended = true
	}

	order := map[string]int{"fits": 0, "tight": 1, "unknown": 2, "too-big": 3}
	slices.SortStableFunc(recs, func(a, b Recommendation) int {
		switch {
		case a.Recommended != b.Recommended:
			if a.Recommended {
				return -1
			}
			return 1
		case order[a.Fit] != order[b.Fit]:
			return order[a.Fit] - order[b.Fit]
		case a.rank != b.rank:
			return b.rank - a.rank
		}
		return int(b.Bytes/1e6 - a.Bytes/1e6)
	})
	return recs
}

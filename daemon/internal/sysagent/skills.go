package sysagent

import (
	"embed"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
)

// Skills are this machine's procedures for sensitive work — SSH keys, Git
// credentials, signing, and each harness's sign-in and config. The chat
// model gets the ones a request touches; a dispatched harness gets the ones
// its plan names.
//
//go:embed skills/*.md
var skillFiles embed.FS

// Skill is one procedure.
type Skill struct {
	ID       string   `json:"id"`
	Title    string   `json:"title"`
	Summary  string   `json:"summary"`
	Keywords []string `json:"keywords"`
	Body     string   `json:"body"`
}

// skillOrder is the order skills are listed in.
var skillOrder = []string{"ssh", "git", "signing", "claude", "codex", "openclaw", "hermes"}

var skills, skillWords = loadSkills()

// loadSkills parses the embedded files: a front matter of title, summary
// and keywords between --- lines, then the body. A malformed file panics at
// start; the embedded set is fixed and tested.
func loadSkills() ([]Skill, map[string][]*regexp.Regexp) {
	out := make([]Skill, 0, len(skillOrder))
	words := map[string][]*regexp.Regexp{}
	for _, id := range skillOrder {
		raw, err := skillFiles.ReadFile("skills/" + id + ".md")
		if err != nil {
			panic(fmt.Sprintf("sysagent: skill %s: %v", id, err))
		}
		head, body, ok := strings.Cut(strings.TrimPrefix(string(raw), "---\n"), "\n---\n")
		if !ok {
			panic(fmt.Sprintf("sysagent: skill %s: no front matter", id))
		}
		s := Skill{ID: id, Body: strings.TrimSpace(body)}
		for _, line := range strings.Split(head, "\n") {
			k, v, _ := strings.Cut(line, ":")
			v = strings.TrimSpace(v)
			switch strings.TrimSpace(k) {
			case "title":
				s.Title = v
			case "summary":
				s.Summary = v
			case "keywords":
				for _, w := range strings.Split(v, ",") {
					if w = strings.ToLower(strings.TrimSpace(w)); w != "" {
						s.Keywords = append(s.Keywords, w)
					}
				}
			}
		}
		if s.Title == "" || s.Summary == "" || len(s.Keywords) == 0 || s.Body == "" {
			panic(fmt.Sprintf("sysagent: skill %s: title, summary, keywords and body are required", id))
		}
		for _, w := range append([]string{id}, s.Keywords...) {
			words[id] = append(words[id], regexp.MustCompile(`(^|[^a-z0-9_])`+regexp.QuoteMeta(w)+`($|[^a-z0-9_])`))
		}
		out = append(out, s)
	}
	return out, words
}

// Skills returns every skill in listing order.
func Skills() []Skill { return slices.Clone(skills) }

// skillByID returns the skill with id.
func skillByID(id string) (Skill, bool) {
	for _, s := range skills {
		if s.ID == id {
			return s, true
		}
	}
	return Skill{}, false
}

// knownSkills keeps the ids that name a skill, once each, in listing order.
func knownSkills(ids []string) []string {
	out := []string{}
	for _, s := range skills {
		if slices.Contains(ids, s.ID) {
			out = append(out, s.ID)
		}
	}
	return out
}

// selectSkills returns up to max skills whose id or keywords appear in
// text as whole words, most hits first.
func selectSkills(text string, max int) []Skill {
	text = strings.ToLower(text)
	type hit struct {
		s Skill
		n int
	}
	var hits []hit
	for _, s := range skills {
		n := 0
		for _, re := range skillWords[s.ID] {
			if re.MatchString(text) {
				n++
			}
		}
		if n > 0 {
			hits = append(hits, hit{s, n})
		}
	}
	sort.SliceStable(hits, func(i, j int) bool { return hits[i].n > hits[j].n })
	out := []Skill{}
	for i := 0; i < len(hits) && i < max; i++ {
		out = append(out, hits[i].s)
	}
	return out
}

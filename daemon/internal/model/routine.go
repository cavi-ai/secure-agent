package model

// RoutineGroup is one process reading one file area, whichever agents ran
// it: the open read-then-connect flags of the window whose read names the
// same process and the same file or home dot-directory. It is served as one
// decision with bulk actions instead of one item per agent.
type RoutineGroup struct {
	// Key is "routine|<reader>|<area>"; it is the id of the group's
	// attention item.
	Key string `json:"key"`
	// Reader is the reading process ("gh", "docker"); empty when the reads
	// recorded none.
	Reader string `json:"reader"`
	// Area is the one file's display path, or ~/.<dir> when the group spans
	// several files under that home dot-directory.
	Area  string `json:"area"`
	Files int    `json:"files"`
	Count int    `json:"count"`
	// Agents are the raising agents, most flags first.
	Agents []string `json:"agents"`
	// Destinations are the busiest PatternListCap orgs (else hosts);
	// DestinationCount counts every distinct one.
	Destinations     []PatternDestination `json:"destinations,omitempty"`
	DestinationCount int                  `json:"destination_count"`
	// Expectable counts the flags whose every read names its reader: the
	// ones Treat as routine resolves.
	Expectable  int             `json:"expectable"`
	Disposition Disposition     `json:"disposition"`
	Summary     string          `json:"summary"`
	Actions     []ExplainAction `json:"actions"`
	// FlagIDs are the covered flags, newest first, at most PatternFlagIDCap.
	FlagIDs []string `json:"flag_ids"`
}

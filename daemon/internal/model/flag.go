package model

import "time"

type Flag struct {
	ID       string    `json:"id"`
	Rule     string    `json:"rule"`
	Severity int       `json:"severity"`
	TS       time.Time `json:"ts"`
	PID      int32     `json:"pid"`
	Agent    string    `json:"agent"`
	Evidence []string  `json:"evidence"`
}

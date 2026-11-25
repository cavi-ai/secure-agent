package main

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"
)

const checkpointSuffix = ".rollup.json"

// rollupCheckpoint records the state through the named rotation sequence.
// Archives through that point remain available to event queries until pruned.
type rollupCheckpoint struct {
	Through int                       `json:"through"`
	Nodes   map[string]nodeCheckpoint `json:"nodes"`
}

type nodeCheckpoint struct {
	State         *NodeState                `json:"state"`
	Recent        []windowEvent             `json:"recent,omitempty"`
	Sessions      map[string]sessionPayload `json:"sessions,omitempty"`
	LastTrace     map[string]tracePayload   `json:"last_trace,omitempty"`
	MaxSeq        uint64                    `json:"max_seq,omitempty"`
	Holes         []sequenceHole            `json:"holes,omitempty"`
	RetiredBoots  []string                  `json:"retired_boots,omitempty"`
	ConfirmedGaps int                       `json:"confirmed_gaps,omitempty"`
	Applied       []appliedDelivery         `json:"applied,omitempty"`
}

func (s *Store) saveCheckpoint(root *os.Root, node string, through int) error {
	checkpoint := rollupCheckpoint{Through: through, Nodes: make(map[string]nodeCheckpoint)}
	for id, rt := range s.nodes {
		if sanitize(id) == node {
			checkpoint.Nodes[id] = nodeCheckpoint{
				State: rt.state, Recent: rt.recent, Sessions: rt.sessions, LastTrace: rt.lastTrace,
				MaxSeq: rt.maxSeq, Holes: rt.holes, RetiredBoots: rt.retiredBoots,
				ConfirmedGaps: rt.confirmedGaps, Applied: rt.applied,
			}
		}
	}

	// Sync the new checkpoint and its directory entry before removing any
	// archive. A restart between rename and removal skips covered archives.
	temp := ".rollup-" + rand.Text() + ".tmp"
	f, err := openEnvelopeLog(root, temp, os.O_CREATE|os.O_EXCL|os.O_WRONLY)
	if err != nil {
		return err
	}
	defer root.Remove(temp)
	if err := json.NewEncoder(f).Encode(checkpoint); err != nil {
		f.Close()
		return err
	}
	if err := errors.Join(f.Sync(), f.Close()); err != nil {
		return err
	}
	if err := root.Rename(temp, node+checkpointSuffix); err != nil {
		return err
	}
	dir, err := root.Open(".")
	if err != nil {
		return err
	}
	return errors.Join(dir.Sync(), dir.Close())
}

func (s *Store) restoreCheckpoint(root *os.Root, name string) (int, error) {
	f, err := openEnvelopeLog(root, name, os.O_RDONLY)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	decoder := json.NewDecoder(f)
	var cp rollupCheckpoint
	if err := decoder.Decode(&cp); err != nil {
		return 0, err
	}
	if err := decoder.Decode(new(json.RawMessage)); err != io.EOF || cp.Through <= 0 || cp.Nodes == nil {
		return 0, errors.New("invalid rollup checkpoint")
	}
	for id, node := range cp.Nodes {
		if node.State == nil || node.State.NodeID != id || sanitize(id)+checkpointSuffix != name {
			return 0, fmt.Errorf("invalid checkpoint state for node %q", id)
		}
		rt := &nodeRuntime{
			state: node.State, recent: node.Recent, sessions: node.Sessions, lastTrace: node.LastTrace,
			maxSeq: node.MaxSeq, holes: node.Holes, retiredBoots: node.RetiredBoots,
			confirmedGaps: node.ConfirmedGaps, applied: node.Applied,
		}
		if len(rt.applied) > 0 {
			rt.appliedAt = make(map[deliveryKey]time.Time, len(rt.applied))
			for _, entry := range rt.applied {
				rt.appliedAt[entry.Key] = entry.At
			}
		}
		s.nodes[id] = rt
	}
	return cp.Through, nil
}

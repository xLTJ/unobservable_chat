//go:build !nocover

package chat

import "time"

const (
	// Cover is true in every normal build.
	// only the nocover build tag, for experiment 2's positive control, turns it off. it can't be changed at run time
	Cover = true

	// Tick is how often cells are sent.
	Tick = 500 * time.Millisecond
)

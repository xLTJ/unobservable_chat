//go:build nocover

package chat

import "time"

const (
	// Cover is false in every nocover build.
	Cover = false

	// Tick is different for nocover build. it is set to 1ms, meaning that messages are sent almost instantly.
	Tick = time.Millisecond
)

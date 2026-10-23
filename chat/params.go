package chat

import "time"

const (
	// RoomCap is how many people can be in a room. locked due to the fixed size of downstream cells.
	// might be increased in the future
	RoomCap = 8

	// CellSize is the total fixed length of a cell.
	// 478 is chosen due to being largest app cell that is always one Tor relay cell, following tests
	CellSize = 478

	// Tick is how often cells are transferred
	Tick = 500 * time.Millisecond

	// JoinTimeout is how many ticks a joiner waits for a reply before giving up.
	// equal to 10 seconds, left long due to Tor being very... unpredicable time-wise
	JoinTimeout = 20

	// DefaultPort is the default port for the relay. Arbitrary, can be whatever.
	DefaultPort = "9735"

	// DefaultSocksAddress is the default socks proxy address.
	DefaultSocksAddress = "127.0.0.1:9052"
)

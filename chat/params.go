package chat

import "time"

const (
	// RoomCap is how many people can be in a room. locked due to the fixed size of downstream cells.
	// might be increased in the future
	RoomCap = 8

	// CellSize is the total fixed length of a cell.
	// 480 is chosen to comfortably fit inside the available space in TOR cells
	CellSize = 480

	// Tick is how often cells are transferred
	Tick = 500 * time.Millisecond

	// DefaultPort is the default port for the relay. Arbitrary, can be whatever.
	DefaultPort = "9735"

	// DefaultSocksAddress is the default socks proxy address.
	DefaultSocksAddress = "127.0.0.1:9052"
)

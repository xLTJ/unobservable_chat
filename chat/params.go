package chat

const (
	// RoomCap is how many people can be in a room. locked due to the fixed size of downstream cells.
	// might be increased in the future
	RoomCap = 8

	// CellSize is the total fixed length of a cell.
	// 480 is chosen to comfortably fit inside the available space in TOR cells
	CellSize = 480

	// Tick is how often cells are transferred
	Tick = 500
)

package chat

import "fmt"

// size of every part of the cell
const (
	KindSize     = 1
	BodySize     = CellSize - KindSize
	NonceSize    = 24 // defined by chacha20poly1305.NonceSizeX
	TagSize      = 16 // defined by chacha20poly1305.Overhead
	PlaintxtSize = BodySize - NonceSize - TagSize
)

type Cell [CellSize]byte
type Kind byte

// kinds of cells
const (
	KindInvalid Kind = iota
	KindData
	KindHandshake
	KindHello
	KindRelayControl
)

type Frame struct {
	Kind Kind
	Body [BodySize]byte
}

// Encode takes a Frame and encodes into a Cell
func (f Frame) Encode() (Cell, error) {
	// invalid kind = instant death
	if f.Kind <= KindInvalid || f.Kind > KindRelayControl {
		return Cell{}, fmt.Errorf("invalid kind: %d", f.Kind)
	}

	var cell Cell
	cell[0] = byte(f.Kind)
	copy(cell[1:], f.Body[:])

	return cell, nil
}

// Decode takes a Cell and decodes into a Frame
func Decode(Cell Cell) (Frame, error) {
	var frame Frame
	frame.Kind = Kind(Cell[0])

	// invalid kind = (almost) instant death
	if frame.Kind <= KindInvalid || frame.Kind > KindRelayControl {
		return Frame{}, fmt.Errorf("invalid kind: %d", frame.Kind)
	}

	copy(frame.Body[:], Cell[1:])
	return frame, nil
}

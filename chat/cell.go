package chat

import (
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

// size of every part of the cell
const (
	KindSize        = 1
	BodySize        = CellSize - KindSize
	NonceSize       = chacha20poly1305.NonceSizeX
	TagSize         = chacha20poly1305.Overhead
	PlaintextSize   = BodySize - NonceSize - TagSize
	InnerHeaderSize = 3 // flag + length
	PayloadMaxSize  = PlaintextSize - InnerHeaderSize
)

type Cell [CellSize]byte
type Kind byte
type Flag byte

// kinds of cells
const (
	KindInvalid Kind = iota
	KindData
	KindHandshake
	KindHello
	KindRelayControl
)

// kinds of flags
const (
	FlagDummy   Flag = 0x00
	FlagMessage Flag = 0x01
)

type Frame struct {
	Kind Kind
	Body [BodySize]byte
}

type Plaintext struct {
	Flag    Flag
	Payload []byte
}

// --------------------------------------------

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
func Decode(c Cell) (Frame, error) {
	var frame Frame
	frame.Kind = Kind(c[0])

	// invalid kind = (almost) instant death
	if frame.Kind <= KindInvalid || frame.Kind > KindRelayControl {
		return Frame{}, fmt.Errorf("invalid kind: %d", frame.Kind)
	}

	copy(frame.Body[:], c[1:])
	return frame, nil
}

// ReadCell reads a Cell from a reader
func ReadCell(r io.Reader) (Cell, error) {
	var buffer Cell

	_, err := io.ReadFull(r, buffer[:])
	return buffer, err
}

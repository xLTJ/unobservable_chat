package chat

import (
	"bytes"
	"errors"
	"io"
	"testing"
	"testing/iotest"
)

// testCell builds an encoded cell of the given kind with a recognisable body.
func testCell(t *testing.T, kind Kind, fill byte) Cell {
	t.Helper()
	var f Frame
	f.Kind = kind
	for i := range f.Body {
		f.Body[i] = fill + byte(i)
	}
	c, err := f.Encode()
	if err != nil {
		t.Fatalf("Encode(kind %d): %v", kind, err)
	}
	return c
}

func TestEncodeDecodeRoundtrip(t *testing.T) {
	for _, kind := range []Kind{KindData, KindHandshake, KindHello, KindRelayControl} {
		var f Frame
		f.Kind = kind
		for i := range f.Body {
			f.Body[i] = byte(i)
		}

		c, err := f.Encode()
		if err != nil {
			t.Fatalf("Encode(kind %d): %v", kind, err)
		}
		if c[0] != byte(kind) {
			t.Errorf("kind %d: type byte is %d", kind, c[0])
		}

		got, err := Decode(c)
		if err != nil {
			t.Fatalf("Decode(kind %d): %v", kind, err)
		}
		if got != f {
			t.Errorf("kind %d: roundtrip changed the frame", kind)
		}
	}
}

func TestInvalidKind(t *testing.T) {
	for _, kind := range []Kind{KindInvalid, KindRelayControl + 1, 0xFF} {
		if _, err := (Frame{Kind: kind}).Encode(); err == nil {
			t.Errorf("Encode accepted kind %d", kind)
		}

		var c Cell
		c[0] = byte(kind)
		if _, err := Decode(c); err == nil {
			t.Errorf("Decode accepted kind %d", kind)
		}
	}

	// an all-zero cell must be rejected (SPEC §3.1)
	if _, err := Decode(Cell{}); err == nil {
		t.Error("Decode accepted an all-zero cell")
	}
}

func TestReadCellPartialReads(t *testing.T) {
	a := testCell(t, KindData, 1)
	b := testCell(t, KindData, 2)

	var stream bytes.Buffer
	stream.Write(a[:])
	stream.Write(b[:])

	// one byte per Read, the worst case a TCP stream can give
	r := iotest.OneByteReader(&stream)

	for i, want := range []Cell{a, b} {
		got, err := ReadCell(r)
		if err != nil {
			t.Fatalf("cell %d: %v", i, err)
		}
		if got != want {
			t.Errorf("cell %d: got different bytes", i)
		}
	}

	// a clean close between cells is io.EOF (SPEC §2)
	if _, err := ReadCell(r); !errors.Is(err, io.EOF) {
		t.Errorf("after the last cell: got %v, want io.EOF", err)
	}
}

func TestReadCellTruncated(t *testing.T) {
	a := testCell(t, KindData, 1)
	b := testCell(t, KindData, 2)

	var stream bytes.Buffer
	stream.Write(a[:])
	stream.Write(b[:CellSize/2])

	got, err := ReadCell(&stream)
	if err != nil {
		t.Fatalf("first cell: %v", err)
	}
	if got != a {
		t.Error("first cell: got different bytes")
	}

	// a close mid-cell is an error, not a clean end (SPEC §2)
	if _, err := ReadCell(&stream); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("half cell: got %v, want io.ErrUnexpectedEOF", err)
	}
}

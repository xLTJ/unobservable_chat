package chat

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"slices"
	"strings"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

// newTestAEAD returns an AEAD under a fresh random key.
func newTestAEAD(t *testing.T) cipher.AEAD {
	t.Helper()
	key := make([]byte, chacha20poly1305.KeySize)
	rand.Read(key)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		t.Fatalf("NewX: %v", err)
	}
	return aead
}

// roundtrip seals p, sends it through Encode and Decode like the wire would, and opens it again.
func roundtrip(t *testing.T, aead cipher.AEAD, p Plaintext) Plaintext {
	t.Helper()
	f, err := SealData(aead, p)
	if err != nil {
		t.Fatalf("SealData: %v", err)
	}
	if f.Kind != KindData {
		t.Fatalf("sealed frame has kind %d, want %d", f.Kind, KindData)
	}

	c, err := f.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	f, err = Decode(c)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}

	got, err := OpenData(aead, f)
	if err != nil {
		t.Fatalf("OpenData: %v", err)
	}
	return got
}

// sealRaw seals a hand-built 437-byte plaintext into a data frame, bypassing SealData's checks.
func sealRaw(aead cipher.AEAD, pt [PlaintextSize]byte) Frame {
	f := Frame{Kind: KindData}
	nonce := f.Body[:NonceSize]
	rand.Read(nonce)
	aead.Seal(f.Body[:NonceSize], nonce, pt[:], []byte{byte(KindData)})
	return f
}

// openRaw opens a data frame and returns the whole 437-byte plaintext, bypassing OpenData's parsing.
func openRaw(t *testing.T, aead cipher.AEAD, f Frame) []byte {
	t.Helper()
	pt, err := aead.Open(nil, f.Body[:NonceSize], f.Body[NonceSize:], []byte{byte(KindData)})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return pt
}

func TestDerivedSizes(t *testing.T) {
	// SPEC §1: these must add up, or the cell layout is wrong
	if PlaintextSize != 437 {
		t.Errorf("PlaintextSize = %d, want 437", PlaintextSize)
	}
	if InnerHeaderSize != 11 {
		t.Errorf("InnerHeaderSize = %d, want 11", InnerHeaderSize)
	}
	if PayloadMaxSize != 426 {
		t.Errorf("PayloadMax = %d, want 426", PayloadMaxSize)
	}
	if NonceSize+PlaintextSize+TagSize != BodySize {
		t.Errorf("nonce + plaintext + tag = %d, want BodySize %d", NonceSize+PlaintextSize+TagSize, BodySize)
	}
}

func TestSealOpenMessage(t *testing.T) {
	aead := newTestAEAD(t)
	want := Plaintext{Flag: FlagMessage, Payload: []byte("hello, room")}

	got := roundtrip(t, aead, want)
	if got.Flag != want.Flag {
		t.Errorf("flag = %#x, want %#x", got.Flag, want.Flag)
	}
	if !bytes.Equal(got.Payload, want.Payload) {
		t.Errorf("payload = %q, want %q", got.Payload, want.Payload)
	}
}

func TestSealOpenDummy(t *testing.T) {
	aead := newTestAEAD(t)

	got := roundtrip(t, aead, Plaintext{Flag: FlagDummy})
	if got.Flag != FlagDummy {
		t.Errorf("flag = %#x, want dummy", got.Flag)
	}
	if len(got.Payload) != 0 {
		t.Errorf("dummy payload has %d bytes, want 0", len(got.Payload))
	}
}

func TestDummyPlaintextIsZero(t *testing.T) {
	aead := newTestAEAD(t)

	// SPEC §4: a dummy has flag 0, len 0 and a zero header, so its whole plaintext is zeros
	f, err := SealData(aead, Plaintext{Flag: FlagDummy})
	if err != nil {
		t.Fatalf("SealData: %v", err)
	}
	if !bytes.Equal(openRaw(t, aead, f), make([]byte, PlaintextSize)) {
		t.Error("dummy plaintext is not all zeros")
	}
}

func TestSealOpenHeader(t *testing.T) {
	aead := newTestAEAD(t)

	// the header fields survive the trip, for a middle fragment and a last one
	for _, last := range []bool{false, true} {
		want := Plaintext{
			Flag:          FlagMessage,
			Payload:       []byte("fragment"),
			Sender:        [4]byte{1, 2, 3, 4},
			MsgNum:        65535,
			FragmentIndex: 9,
			Last:          last,
		}
		got := roundtrip(t, aead, want)
		if got.Sender != want.Sender || got.MsgNum != want.MsgNum || got.FragmentIndex != want.FragmentIndex || got.Last != want.Last {
			t.Errorf("header = sender % x, msg %d, index %d, last %v; want sender % x, msg %d, index %d, last %v",
				got.Sender, got.MsgNum, got.FragmentIndex, got.Last, want.Sender, want.MsgNum, want.FragmentIndex, want.Last)
		}
		if !bytes.Equal(got.Payload, want.Payload) {
			t.Errorf("payload = %q, want %q", got.Payload, want.Payload)
		}
	}
}

func TestHeaderLayout(t *testing.T) {
	aead := newTestAEAD(t)

	// a roundtrip passes with any layout that seal and open agree on, so check the bytes against SPEC §3.3
	p := Plaintext{
		Flag:          FlagMessage,
		Payload:       []byte("hi"),
		Sender:        [4]byte{0xde, 0xad, 0xbe, 0xef},
		MsgNum:        0x1234,
		FragmentIndex: 9,
		Last:          true,
	}
	f, err := SealData(aead, p)
	if err != nil {
		t.Fatalf("SealData: %v", err)
	}
	pt := openRaw(t, aead, f)

	// flag 0, len 1–2, sender 3–6, msg 7–8, frag 9, last 10, payload from 11, then zeros
	want := []byte{0x01, 0x00, 0x02, 0xde, 0xad, 0xbe, 0xef, 0x12, 0x34, 9, 0x01, 'h', 'i'}
	if !bytes.Equal(pt[:len(want)], want) {
		t.Errorf("plaintext starts % x, want % x", pt[:len(want)], want)
	}
	if !bytes.Equal(pt[len(want):], make([]byte, PlaintextSize-len(want))) {
		t.Error("padding after the payload is not all zeros")
	}
}

func TestSealRejectsBadPlaintext(t *testing.T) {
	aead := newTestAEAD(t)

	// SealData never makes a cell the receiver would reject (SPEC §3.3): a message carries
	// 1–PayloadMax bytes, a dummy none, and the flag is one of the two
	cases := map[string]Plaintext{
		"message with no payload": {Flag: FlagMessage, Payload: []byte{}},
		"dummy with a payload":    {Flag: FlagDummy, Payload: []byte("x")},
		"invalid flag":            {Flag: FlagMessage + 1, Payload: []byte("x")},
	}
	for what, p := range cases {
		if _, err := SealData(aead, p); err == nil {
			t.Errorf("%s: SealData accepted it", what)
		}
	}
}

func TestPayloadMax(t *testing.T) {
	aead := newTestAEAD(t)

	// exactly PayloadMax bytes fits
	full := bytes.Repeat([]byte{'x'}, PayloadMaxSize)
	got := roundtrip(t, aead, Plaintext{Flag: FlagMessage, Payload: full})
	if !bytes.Equal(got.Payload, full) {
		t.Error("a PayloadMax message came back different")
	}

	// one more byte is rejected, never truncated (D-044)
	over := bytes.Repeat([]byte{'x'}, PayloadMaxSize+1)
	if _, err := SealData(aead, Plaintext{Flag: FlagMessage, Payload: over}); err == nil {
		t.Error("SealData accepted a payload of PayloadMax+1 bytes")
	}
}

func TestOpenRejectsBadPlaintext(t *testing.T) {
	aead := newTestAEAD(t)

	// these cells open fine, so the sender had the key, but the plaintext is invalid (SPEC §4 step 3).
	// offsets from SPEC §3.3: flag 0, len 1–2, sender 3–6, msg 7–8, frag 9, last 10, payload from 11
	var badFlag [PlaintextSize]byte
	badFlag[0] = byte(FlagMessage) + 1

	var badLen [PlaintextSize]byte
	badLen[0] = byte(FlagMessage)
	binary.BigEndian.PutUint16(badLen[1:3], PayloadMaxSize+1)

	var emptyMessage [PlaintextSize]byte
	emptyMessage[0] = byte(FlagMessage)
	emptyMessage[10] = 0x01 // a valid one-cell message, apart from len 0

	var dummyWithLen [PlaintextSize]byte
	dummyWithLen[0] = byte(FlagDummy)
	binary.BigEndian.PutUint16(dummyWithLen[1:3], 1)

	var badLast [PlaintextSize]byte
	badLast[0] = byte(FlagMessage)
	binary.BigEndian.PutUint16(badLast[1:3], 1)
	badLast[10] = 0x02
	badLast[11] = 'x'

	cases := map[string][PlaintextSize]byte{
		"invalid flag":        badFlag,
		"len over PayloadMax": badLen,
		"message with len 0":  emptyMessage,
		"dummy with len 1":    dummyWithLen,
		"last not 0 or 1":     badLast,
	}
	for name, pt := range cases {
		_, err := OpenData(aead, sealRaw(aead, pt))
		if err == nil {
			t.Errorf("%s: OpenData accepted it", name)
		}
		// the caller logs these but drops ErrOpen silently, so they must not look alike
		if errors.Is(err, ErrOpen) {
			t.Errorf("%s: got ErrOpen, want a plaintext error", name)
		}
	}
}

func TestFillerFrame(t *testing.T) {
	// SPEC §6.2: a data-type cell with 477 random bytes
	f := MakeFillerFrame()
	if f.Kind != KindData {
		t.Errorf("filler kind = %d, want %d", f.Kind, KindData)
	}
	if f.Body == [BodySize]byte{} {
		t.Error("filler body is all zeros, want random bytes")
	}
	if _, err := f.Encode(); err != nil {
		t.Errorf("Encode: %v", err)
	}
}

func TestBuildBodyLayout(t *testing.T) {
	// SPEC §3.4: name_len | name | text
	got, err := BuildBody("alice", "hello")
	if err != nil {
		t.Fatalf("BuildBody: %v", err)
	}
	want := append([]byte{5}, "alicehello"...)
	if !bytes.Equal(got, want) {
		t.Errorf("body = % x, want % x", got, want)
	}
}

func TestBodyRoundtrip(t *testing.T) {
	cases := []struct{ name, text string }{
		{"alice", "hello"},
		{"Søren", "æøå and 日本語"},                      // multi-byte UTF-8 in both fields
		{strings.Repeat("n", DisplayNameMaxLen), "x"}, // longest name
		{strings.Repeat("ø", 16), "x"},                // 16 characters but 32 bytes: still fits, the limit is in bytes
		{"a", strings.Repeat("t", MessageMaxLen)},     // longest text
	}
	for _, c := range cases {
		body, err := BuildBody(c.name, c.text)
		if err != nil {
			t.Errorf("BuildBody(%q, %d bytes of text): %v", c.name, len(c.text), err)
			continue
		}
		name, text, err := ParseBody(body)
		if err != nil {
			t.Errorf("ParseBody of %q's body: %v", c.name, err)
			continue
		}
		if name != c.name || text != c.text {
			t.Errorf("got (%q, %d bytes of text), want (%q, %d bytes of text)", name, len(text), c.name, len(c.text))
		}
	}
}

func TestBuildBodyRejects(t *testing.T) {
	// SPEC §3.4: name 1–NAME_MAX bytes of valid UTF-8, text 1–MAX_MESSAGE bytes
	cases := map[string]struct{ name, text string }{
		"empty name":              {"", "hello"},
		"name over 32 bytes":      {strings.Repeat("n", DisplayNameMaxLen+1), "hello"},
		"17 characters, 34 bytes": {strings.Repeat("ø", 17), "hello"}, // counting characters instead of bytes would let this through
		"name not UTF-8":          {"\xff", "hello"},
		"empty text":              {"alice", ""},
		"text over 4096 bytes":    {"alice", strings.Repeat("t", MessageMaxLen+1)},
	}
	for what, c := range cases {
		if _, err := BuildBody(c.name, c.text); err == nil {
			t.Errorf("%s: BuildBody accepted it", what)
		}
	}
}

func TestParseBodyRejects(t *testing.T) {
	// SPEC §3.4: a body that doesn't parse is dropped and logged
	cases := map[string][]byte{
		"empty body":            {},
		"name_len 0":            append([]byte{0}, "hello"...),
		"name_len 33":           append([]byte{33}, strings.Repeat("n", 33)+"hello"...),
		"name_len past the end": append([]byte{10}, "abc"...),
		"name not UTF-8":        {1, 0xff, 'h', 'i'},
		"no text":               append([]byte{5}, "alice"...),
		"text over 4096 bytes":  append([]byte{5}, "alice"+strings.Repeat("t", MessageMaxLen+1)...),
	}
	for what, body := range cases {
		if _, _, err := ParseBody(body); err == nil {
			t.Errorf("%s: ParseBody accepted it", what)
		}
	}
}

func TestSplitBody(t *testing.T) {
	// SPEC §1 "Body max": the longest body splits into exactly 10 pieces ("Fragments max")
	maxBody := 1 + DisplayNameMaxLen + MessageMaxLen
	longest := make([]int, 0, 10)
	for range 9 {
		longest = append(longest, PayloadMaxSize)
	}
	longest = append(longest, maxBody-9*PayloadMaxSize)

	cases := []struct {
		size int
		want []int // the size of each piece
	}{
		{1, []int{1}},
		{PayloadMaxSize, []int{PayloadMaxSize}},                     // exactly one full cell
		{PayloadMaxSize + 1, []int{PayloadMaxSize, 1}},              // one byte over: two cells
		{2 * PayloadMaxSize, []int{PayloadMaxSize, PayloadMaxSize}}, // exactly two full cells, no empty third
		{maxBody, longest},
	}
	for _, c := range cases {
		body := make([]byte, c.size)
		for i := range body {
			body[i] = byte(i % 251) // doesn't repeat at the piece size, so a misplaced piece shows
		}
		pieces := SplitBody(body)

		sizes := make([]int, len(pieces))
		for i, p := range pieces {
			sizes[i] = len(p)
		}
		if !slices.Equal(sizes, c.want) {
			t.Errorf("%d-byte body: piece sizes %v, want %v", c.size, sizes, c.want)
		}
		if !bytes.Equal(bytes.Join(pieces, nil), body) {
			t.Errorf("%d-byte body: the pieces don't join back into the body", c.size)
		}
	}
}

func TestLongMessageThroughCells(t *testing.T) {
	// the send and receive paths in a row, without the network or reassembly:
	// a 2,000-byte line becomes 5 cells and comes back whole, with the name
	aead := newTestAEAD(t)
	text := strings.Repeat("0123456789", 200)

	body, err := BuildBody("alice", text)
	if err != nil {
		t.Fatalf("BuildBody: %v", err)
	}
	pieces := SplitBody(body)
	if len(pieces) != 5 {
		t.Fatalf("a %d-byte body split into %d pieces, want 5", len(body), len(pieces))
	}

	var joined []byte
	for i, piece := range pieces {
		p := Plaintext{
			Flag:          FlagMessage,
			Payload:       piece,
			Sender:        [4]byte{1, 2, 3, 4},
			MsgNum:        7,
			FragmentIndex: byte(i),
			Last:          i == len(pieces)-1,
		}
		got := roundtrip(t, aead, p)
		if got.FragmentIndex != p.FragmentIndex || got.Last != p.Last {
			t.Errorf("piece %d: index %d, last %v; want index %d, last %v", i, got.FragmentIndex, got.Last, p.FragmentIndex, p.Last)
		}
		joined = append(joined, got.Payload...)
	}

	name, gotText, err := ParseBody(joined)
	if err != nil {
		t.Fatalf("ParseBody: %v", err)
	}
	if name != "alice" || gotText != text {
		t.Errorf("got (%q, %d bytes of text), want (%q, %d bytes of text)", name, len(gotText), "alice", len(text))
	}
}

package chat

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
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

func TestDerivedSizes(t *testing.T) {
	// SPEC §1: these must add up, or the cell layout is wrong
	if PlaintextSize != 437 {
		t.Errorf("PlaintextSize = %d, want 437", PlaintextSize)
	}
	if PayloadMaxSize != 434 {
		t.Errorf("PayloadMax = %d, want 434", PayloadMaxSize)
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

func TestSealOpenEmptyMessage(t *testing.T) {
	aead := newTestAEAD(t)

	// an empty message is still a message, not a dummy
	got := roundtrip(t, aead, Plaintext{Flag: FlagMessage, Payload: []byte{}})
	if got.Flag != FlagMessage {
		t.Errorf("flag = %#x, want message", got.Flag)
	}
	if len(got.Payload) != 0 {
		t.Errorf("payload has %d bytes, want 0", len(got.Payload))
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

	// these cells open fine, so the sender had the key, but the plaintext is invalid (SPEC §4 step 3)
	var badFlag [PlaintextSize]byte
	badFlag[0] = byte(FlagMessage) + 1

	var badLen [PlaintextSize]byte
	badLen[0] = byte(FlagMessage)
	binary.BigEndian.PutUint16(badLen[1:3], PayloadMaxSize+1)

	for name, pt := range map[string][PlaintextSize]byte{"invalid flag": badFlag, "len over PayloadMax": badLen} {
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

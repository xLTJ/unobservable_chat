package chat

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"
)

// ---------------- security tests ---------------------
// aka the ones that actually matter for the report

// TestOpenRejectsTamperedBody checks if OpenData correctly rejects a tampered body
func TestOpenRejectsTamperedBody(t *testing.T) {
	aead := newTestAEAD(t)
	plaintext := Plaintext{Flag: FlagMessage, Payload: []byte("hello, glorp")}
	f, err := SealData(aead, plaintext)
	if err != nil {
		t.Fatalf("SealData: %v", err)
	}

	// control: open the frame with no errors
	_, err = OpenData(aead, f)
	if err != nil {
		t.Fatalf("OpenData: %v", err)
	}

	// flip one bit at start and end of each part, and check that OpenData rejects it
	bitsToFlip := []int{0, NonceSize - 1, NonceSize, NonceSize + PlaintextSize - 1, NonceSize + PlaintextSize, BodySize - 1}
	for _, i := range bitsToFlip {
		f.Body[i] ^= 1
		_, err := OpenData(aead, f)

		if !errors.Is(err, ErrOpen) {
			t.Errorf("tampered body at %d: got %v, want ErrOpen", i, err)
		}

		f.Body[i] ^= 1 // flip back to test each individually
	}
}

// TestOpenRejectsChangedAD checks if OpenData correctly rejects a frame with a different AD
func TestOpenRejectsChangedAD(t *testing.T) {
	aead := newTestAEAD(t)
	plaintext := Plaintext{Flag: FlagMessage, Payload: []byte("hello, gleeb")}
	f, err := SealData(aead, plaintext)
	if err != nil {
		t.Fatalf("SealData: %v", err)
	}

	// control: open the frame with expected AD
	controlAd := []byte{byte(KindData)}
	controlNonce := f.Body[:NonceSize]
	_, err = aead.Open(nil, controlNonce, f.Body[NonceSize:], controlAd)
	if err != nil {
		t.Fatalf("aead.Open: %v", err)
	}

	// open with a different type byte
	ad := []byte{byte(KindRelayControl)}
	nonce := f.Body[:NonceSize]
	_, err = aead.Open(nil, nonce, f.Body[NonceSize:], ad)
	if err == nil {
		t.Error("aead.Open accepted a frame with a different type byte")
	}
}

// TestOpenRejectsWrongKey checks if OpenData correctly rejects a frame when given a different key
func TestOpenRejectsWrongKey(t *testing.T) {
	aead := newTestAEAD(t)
	plaintext := Plaintext{Flag: FlagMessage, Payload: []byte("hello, gnarp")}
	f, err := SealData(aead, plaintext)
	if err != nil {
		t.Fatalf("SealData: %v", err)
	}

	// control: open the frame with no errors
	_, err = OpenData(aead, f)
	if err != nil {
		t.Fatalf("OpenData: %v", err)
	}

	newAEAD := newTestAEAD(t)
	_, err = OpenData(newAEAD, f)
	if !errors.Is(err, ErrOpen) {
		t.Error("OpenData accepted a frame with a different key")
	}
}

// TestOpenRejectsFiller checks if OpenData correctly rejects a KindData frame with filler as its body
func TestOpenRejectsFiller(t *testing.T) {
	var filler [BodySize]byte
	rand.Read(filler[:])

	frame := Frame{
		Kind: KindData,
		Body: filler,
	}

	aead := newTestAEAD(t)
	_, err := OpenData(aead, frame)
	if !errors.Is(err, ErrOpen) {
		t.Error("OpenData accepted a frame with filler")
	}
}

// TestDummiesDiffer checks if two dummies created in a row with the same key have different bodies
func TestDummiesDiffer(t *testing.T) {
	aead := newTestAEAD(t)

	// seal two dummies in a row
	var frames [2]Frame
	for i := range frames {
		plaintext := Plaintext{Flag: FlagDummy}
		f, err := SealData(aead, plaintext)
		if err != nil {
			t.Fatalf("SealData: %v", err)
		}
		frames[i] = f
	}

	if bytes.Equal(frames[0].Body[:], frames[1].Body[:]) {
		t.Error("two dummies sealed in a row had the same nonce")
	}
}

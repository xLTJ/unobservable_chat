package chat

import (
	"bytes"
	"crypto/hkdf"
	"crypto/sha256"
	"testing"

	"filippo.io/cpace"
	"golang.org/x/crypto/chacha20poly1305"
)

// TestOnboardWrongPasswordRefused checks that a joiner with the wrong password gets no K_room.
func TestOnboardWrongPasswordRefused(t *testing.T) {
	kRoom := randomBytes(32)

	// control test with the same password
	got, err := onboard(t, "gleeb glorp strong password", "gleeb glorp strong password", kRoom)
	if err != nil {
		t.Fatalf("OpenWrap: %v", err)
	}
	if !bytes.Equal(got, kRoom) {
		t.Errorf("the joiner got a different K_room for the same password")
	}

	// now with different passwords
	got, err = onboard(t, "gleeb glorp strong password", "wrong password", kRoom)
	if err == nil {
		t.Errorf("the joiner got the same K_room with the wrong password")
	}
	if got != nil {
		t.Errorf("the joiner got some kind of K_room with the wrong password")
	}

	// and where the difference is only in case
	got, err = onboard(t, "glorp", "Glorp", kRoom)
	if err == nil {
		t.Errorf("the joiner got the same K_room with the wrong password")
	}
	if got != nil {
		t.Errorf("the joiner got some kind of K_room with the wrong password")
	}

	// finally only adding a trailing space
	got, err = onboard(t, "glorp ", "glorp", kRoom)
	if err == nil {
		t.Errorf("the joiner got the same K_room with the wrong password")
	}
	if got != nil {
		t.Errorf("the joiner got some kind of K_room with the wrong password")
	}
}

// TestOpenWrapRejectsTampered checks that a changed wrap never opens.
func TestOpenWrapRejectsTampered(t *testing.T) {
	kRoom := randomBytes(32)
	isk := randomBytes(32)
	wrap, err := SealWrap(isk, kRoom)
	if err != nil {
		t.Fatalf("SealWrap: %v", err)
	}

	// control test with no tampering
	got, err := OpenWrap(isk, wrap)
	if err != nil {
		t.Errorf("failed to open wrap with no tampering")
	}
	if !bytes.Equal(got, kRoom) {
		t.Errorf("the joiner got a different K_room with no tampering")
	}

	// flip one bit at start and end of each part, and check that OpenWrap rejects it
	bitsToFlip := []int{0, NonceSize - 1, NonceSize, NonceSize + 31, NonceSize + 32, WrapSize - 1}
	for _, i := range bitsToFlip {
		wrap[i] ^= 1
		got, err = OpenWrap(isk, wrap)

		if err == nil {
			t.Errorf("tampered wrap at %d: got no error, want one", i)
		}
		if bytes.Equal(got, kRoom) {
			t.Errorf("tampered wrap at %d: got the correct K_room, want different", i)
		}

		wrap[i] ^= 1 // flip back to test each individually
	}
}

// TestOpenWrapRejectsWrongISK checks that a wrap only opens under the ISK it was sealed with.
func TestOpenWrapRejectsWrongISK(t *testing.T) {
	kRoom := randomBytes(32)
	isk := randomBytes(32)

	wrap, err := SealWrap(isk, kRoom)
	if err != nil {
		t.Fatalf("SealWrap: %v", err)
	}

	// control test with the same ISK
	_, err = OpenWrap(isk, wrap)
	if err != nil {
		t.Errorf("failed to open wrap with the same ISK")
	}

	// now with a different ISK
	isk = randomBytes(32)
	_, err = OpenWrap(isk, wrap)
	if err == nil {
		t.Errorf("wrap with the wrong ISK opened")
	}
}

// TestWrapRejectsOtherAD checks that the wrap is bound to the handshake type byte
func TestWrapRejectsOtherAD(t *testing.T) {
	isk := randomBytes(32)
	kRoom := randomBytes(32)
	wrap, err := SealWrap(isk, kRoom)
	if err != nil {
		t.Fatalf("SealWrap: %v", err)
	}

	// this key will be the same as the one used inside SealWrap, as all data is the same
	wrapKey, err := hkdf.Expand(sha256.New, isk, wrapLabel, 32)
	aead, err := chacha20poly1305.NewX(wrapKey)

	nonce := wrap[:NonceSize]

	// control: aead.Open with AD = KindHandshake opens
	ad := []byte{byte(KindHandshake)}
	_, err = aead.Open(nil, nonce, wrap[NonceSize:], ad)
	if err != nil {
		t.Errorf("failed to open wrap with the same ISK")
	}

	// now with a different AD, and check that OpenData rejects it
	ad = []byte{byte(KindData)}
	_, err = aead.Open(nil, nonce, wrap[NonceSize:], ad)
	if err == nil {
		t.Errorf("wrap with the wrong AD opened")
	}
}

// TestContextBindsAD checks that both sides must use the same CPace context.
func TestContextBindsAD(t *testing.T) {
	password := "gleep glorp strong password"

	// control: both sides use the same context
	msgA, state, err := cpace.Start(password, MakeCpaceContext())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	msgB, memberISK, err := cpace.Exchange(password, MakeCpaceContext(), msgA)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	joinerISK, err := state.Finish(msgB)
	if err != nil {
		t.Fatalf("Finish: %v", err)
	}
	if !bytes.Equal(joinerISK, memberISK) {
		t.Errorf("the two sides got different ISKs when using the same context")
	}

	// now with a different context (using some random ad)
	msgA, state, err = cpace.Start(password, MakeCpaceContext())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	msgB, memberISK, err = cpace.Exchange(password, cpace.NewContextInfo("", "", []byte("i hate glorp")), msgA)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	joinerISK, err = state.Finish(msgB)
	if err != nil {
		t.Fatalf("Finish: %v", err)
	}
	if bytes.Equal(joinerISK, memberISK) {
		t.Errorf("the two sides got the same ISK when using different contexts")
	}
}

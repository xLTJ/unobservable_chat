package chat

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
)

func MakeFillerFrame() Frame {
	f := Frame{Kind: KindData}
	_, _ = rand.Read(f.Body[:])
	return f
}

func SealData(aead cipher.AEAD, p Plaintext) (Frame, error) {
	if len(p.Payload) > PayloadMaxSize {
		return Frame{}, fmt.Errorf("payload too long: %d > %d", len(p.Payload), PayloadMaxSize)
	}

	var plaintextArray [PlaintextSize]byte

	// construct plaintext
	plaintextArray[0] = byte(p.Flag)
	binary.BigEndian.PutUint16(plaintextArray[1:], uint16(len(p.Payload))) // put len at bytes 1-2
	copy(plaintextArray[3:], p.Payload)

	// generate nonce
	nonce := make([]byte, NonceSize)
	if _, err := rand.Read(nonce[:]); err != nil {
		return Frame{}, fmt.Errorf("failed to generate nonce: %v", err)
	}

	// sealing
	ad := []byte{byte(KindData)} // relay needs to see the kind of cell, so has to be in AD
	var body [BodySize]byte
	copy(body[:NonceSize], nonce)
	out := aead.Seal(nil, nonce, plaintextArray[:], ad)
	copy(body[NonceSize:], out)

	return Frame{
		Kind: KindData,
		Body: body,
	}, nil
}

var ErrOpen = errors.New("cell failed to open") // sentinel error when opening fails

func OpenData(aead cipher.AEAD, f Frame) (Plaintext, error) {
	if f.Kind != KindData {
		return Plaintext{}, fmt.Errorf("frame has kind %d, want %d", f.Kind, KindData)
	}

	// opening
	nonce := f.Body[:NonceSize]
	ad := []byte{byte(KindData)}
	plaintext, err := aead.Open(nil, nonce, f.Body[NonceSize:], ad)
	if err != nil {
		return Plaintext{}, ErrOpen
	}

	// parse flag and length
	flag := Flag(plaintext[0])
	length := binary.BigEndian.Uint16(plaintext[1:])

	// check validity
	if flag != FlagDummy && flag != FlagMessage {
		return Plaintext{}, fmt.Errorf("invalid flag: %d", flag)
	}
	if length > PayloadMaxSize {
		return Plaintext{}, fmt.Errorf("invalid length: %d", length)
	}
	payload := plaintext[InnerHeaderSize : InnerHeaderSize+length]

	return Plaintext{
		Flag:    flag,
		Payload: payload,
	}, nil
}

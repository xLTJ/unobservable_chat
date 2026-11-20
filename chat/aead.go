package chat

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"unicode/utf8"
)

func MakeFillerFrame() Frame {
	f := Frame{Kind: KindData}
	_, _ = rand.Read(f.Body[:])
	return f
}

// SealData encrypts plaintext into a data frame
func SealData(aead cipher.AEAD, p Plaintext) (Frame, error) {
	if p.Flag != FlagDummy && p.Flag != FlagMessage {
		return Frame{}, fmt.Errorf("invalid flag: %d", p.Flag)
	}

	if len(p.Payload) > PayloadMaxSize {
		return Frame{}, fmt.Errorf("payload too long: %d", len(p.Payload))
	}

	if p.Flag == FlagMessage && len(p.Payload) == 0 {
		return Frame{}, fmt.Errorf("payload too short: %d", len(p.Payload))
	}
	if p.Flag == FlagDummy && len(p.Payload) != 0 {
		return Frame{}, fmt.Errorf("dummy payload has %d bytes, want 0", len(p.Payload))
	}

	var plaintextArray [PlaintextSize]byte
	unwritten := plaintextArray[:] // pointer to the next unwritten byte in plaintextArray

	// construct plaintext
	unwritten[0], unwritten = byte(p.Flag), unwritten[InnerHeaderFlagSize:]

	binary.BigEndian.PutUint16(unwritten[:InnerHeaderLenSize], uint16(len(p.Payload)))
	unwritten = unwritten[InnerHeaderLenSize:]

	copy(unwritten, p.Sender[:])
	unwritten = unwritten[InnerHeaderSenderSize:]

	binary.BigEndian.PutUint16(unwritten[:InnerHeaderMsgNumSize], p.MsgNum)
	unwritten = unwritten[InnerHeaderMsgNumSize:]

	unwritten[0], unwritten = p.FragmentIndex, unwritten[InnerHeaderIndexSize:]

	if p.Last {
		unwritten[0] = 1
	} else {
		unwritten[0] = 0
	}
	unwritten = unwritten[InnerHeaderLastSize:]
	copy(unwritten, p.Payload)

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

func BuildBody(name, text string) ([]byte, error) {
	// reject all bad and evil inputs
	if len(name) == 0 || len(text) == 0 {
		return nil, fmt.Errorf("name or text is empty")
	}

	if len(name) > DisplayNameMaxLen || len(text) > MessageMaxLen {
		return nil, fmt.Errorf("name or text too long")
	}

	if !utf8.ValidString(name) {
		return nil, fmt.Errorf("invalid name")
	}

	// finally, we can actually build the body
	var body []byte
	body = append(body, byte(len(name)))
	body = append(body, name...)
	body = append(body, text...)
	return body, nil
}

func ParseBody(body []byte) (name, text string, err error) {
	// body completely empty? death
	if len(body) == 0 {
		return "", "", fmt.Errorf("body is empty")
	}

	// invalid name length? death
	nameLen := int(body[0])
	if nameLen == 0 || nameLen > DisplayNameMaxLen || nameLen > len(body)-1 {
		return "", "", fmt.Errorf("invalid name length: %d", nameLen)
	}

	// extract name and text
	name = string(body[1 : 1+nameLen])
	text = string(body[1+nameLen:])

	// invalid name? death
	if !utf8.ValidString(name) {
		return "", "", fmt.Errorf("invalid name: %q", name)
	}

	// invalid text? believe it or not, death
	if len(text) > MessageMaxLen || len(text) == 0 {
		return "", "", fmt.Errorf("invalid text length: %d", len(text))
	}

	return
}

// SplitBody splits a body into a slice of pieces of PayloadMaxSize length
func SplitBody(body []byte) [][]byte {
	var pieces [][]byte
	for i := 0; i < len(body); i += PayloadMaxSize {
		// if the remainder is less than PayloadMaxSize, append it as a smaller piece and break the loop
		if i+PayloadMaxSize > len(body) {
			pieces = append(pieces, body[i:])
			break
		}
		pieces = append(pieces, body[i:i+PayloadMaxSize])
	}

	return pieces
}

var ErrOpen = errors.New("cell failed to open") // sentinel error when opening fails

// OpenData decrypts a data frame
func OpenData(aead cipher.AEAD, f Frame) (Plaintext, error) {
	if f.Kind != KindData {
		return Plaintext{}, fmt.Errorf("frame has kind %d, want %d", f.Kind, KindData)
	}

	// opening
	nonce := f.Body[:NonceSize]
	ad := []byte{byte(KindData)}
	plaintextBytes, err := aead.Open(nil, nonce, f.Body[NonceSize:], ad)
	if err != nil {
		return Plaintext{}, ErrOpen
	}

	// parse flag and length
	var plaintext Plaintext

	// the parser of doom and despair
	plaintext.Flag, plaintextBytes = Flag(plaintextBytes[0]), plaintextBytes[InnerHeaderFlagSize:]
	payloadLength, plaintextBytes := binary.BigEndian.Uint16(plaintextBytes[:InnerHeaderLenSize]), plaintextBytes[InnerHeaderLenSize:]
	plaintext.Sender, plaintextBytes = [4]byte(plaintextBytes[:InnerHeaderSenderSize]), plaintextBytes[InnerHeaderSenderSize:]
	plaintext.MsgNum, plaintextBytes = binary.BigEndian.Uint16(plaintextBytes[:InnerHeaderMsgNumSize]), plaintextBytes[InnerHeaderMsgNumSize:]
	plaintext.FragmentIndex, plaintextBytes = plaintextBytes[0], plaintextBytes[InnerHeaderIndexSize:]
	lastByte, plaintextBytes := plaintextBytes[0], plaintextBytes[InnerHeaderLastSize:]

	if lastByte != 0 && lastByte != 1 {
		return Plaintext{}, fmt.Errorf("invalid last byte: %d", lastByte)
	}
	plaintext.Last = lastByte == 1

	// check validity
	if plaintext.Flag != FlagDummy && plaintext.Flag != FlagMessage {
		return Plaintext{}, fmt.Errorf("invalid flag: %d", plaintext.Flag)
	}
	if payloadLength > PayloadMaxSize {
		return Plaintext{}, fmt.Errorf("payload too long: %d", payloadLength)
	}
	if plaintext.Flag == FlagMessage && payloadLength == 0 {
		return Plaintext{}, fmt.Errorf("payload too short: %d", payloadLength)
	}
	if plaintext.Flag == FlagDummy && payloadLength != 0 {
		return Plaintext{}, fmt.Errorf("dummy payload has %d bytes, want 0", payloadLength)
	}

	plaintext.Payload = plaintextBytes[:payloadLength]

	return plaintext, nil
}

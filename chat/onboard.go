package chat

import (
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"slices"

	"filippo.io/cpace"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/text/secure/precis"
)

// labels used in the onboarding
const (
	contextLabel = "unobservable-chat v1 cpace" // used in the AD given to the context
	wrapLabel    = "unobservable-chat v1 wrap"  // used in the label of the HKDF
)

// sizes used for the onboarding cells
const (
	PointSize = 32 // only used to derive other sizes. all public values exchanged (like Ya and Yb) are points

	SubtypeSize = 1
	SidSize     = 16
	MsgASize    = SidSize + PointSize
	MsgBSize    = PointSize
	WrapSize    = NonceSize + chacha20poly1305.KeySize + TagSize
)

type Subtype byte

const (
	SubtypeMsgA Subtype = iota + 1
	SubtypeReply
)

type Handshake struct {
	Subtype Subtype
	MsgA    []byte // msgA only
	Sid     []byte // reply only
	MsgB    []byte // reply only
	Wrap    []byte // reply only
}

// ------------- frame factories ------------

func MakeControlFrame(earlier int) Frame {
	return Frame{
		Kind: KindRelayControl,
		Body: [BodySize]byte{byte(earlier)},
	}
}

func MakeMsgAFrame(msgA []byte) Frame {
	f := Frame{Kind: KindHandshake}

	// set subtype and msgA
	f.Body[0] = byte(SubtypeMsgA)
	copy(f.Body[1:], msgA)
	return f
}

func MakeReplyFrame(sid, msgB, wrap []byte) Frame {
	f := Frame{Kind: KindHandshake}
	f.Body[0] = byte(SubtypeReply)
	copy(f.Body[1:], slices.Concat(sid, msgB, wrap))
	return f
}

// -------------- frame parsers --------------

// ParseControl parses a control frame and returns the earlier value
func ParseControl(f Frame) (earlier int, err error) {
	if f.Kind != KindRelayControl {
		return 0, fmt.Errorf("frame is not a control frame")
	}
	return int(f.Body[0]), nil
}

func ParseHandshake(f Frame) (h Handshake, err error) {
	if f.Kind != KindHandshake {
		return Handshake{}, fmt.Errorf("frame is not a handshake frame")
	}

	// parse sub-type and body and set fields accordingly
	h.Subtype = Subtype(f.Body[0])
	b := f.Body[SubtypeSize:]

	switch h.Subtype {
	case SubtypeMsgA:
		h.MsgA = f.Body[1 : 1+MsgASize]
	case SubtypeReply:
		h.Sid, b = b[:SidSize], b[SidSize:]
		h.MsgB, b = b[:MsgBSize], b[MsgBSize:]
		h.Wrap = b[:WrapSize]
	default:
		return Handshake{}, fmt.Errorf("invalid sub-type: %d", h.Subtype)
	}

	return h, nil
}

// ------------- onboarding functions ------------

// NormalisePassword returns a string that is suitable for use as a password.
// as specified in the CPACE spec, the password "SHOULD BE encoded according to [RFC8265]", which is done here.
// this prevents the same password typed on different systems from giving different bytes.
func NormalisePassword(password string) (string, error) {
	return precis.OpaqueString.String(password)
}

// CPaceContext returns a context info object that can be used to create a CPace context
func CPaceContext() *cpace.ContextInfo {
	// include length in the AD, as the label length is variable
	length := uint16(len(contextLabel))
	ad := binary.BigEndian.AppendUint16(nil, length)
	ad = append(ad, contextLabel...)

	return cpace.NewContextInfo("", "", ad)
}

// SealWrap seals the provided kRoom key using the isk input and returns a wrap
func SealWrap(isk, kRoom []byte) ([]byte, error) {
	// first, derive the key for the wrap
	// as isk is already pseudorandom, we can use it directly as the key, skipping the extract step of HKDF
	wrapKey, err := hkdf.Expand(sha256.New, isk, wrapLabel, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate wrap key: %v", err)
	}

	// now for the wrap itself
	aead, err := chacha20poly1305.NewX(wrapKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AEAD: %v", err)
	}

	nonce := make([]byte, NonceSize)
	_, _ = rand.Read(nonce[:])

	ad := []byte{byte(KindHandshake)}
	var wrap [WrapSize]byte
	copy(wrap[:NonceSize], nonce)
	out := aead.Seal(nil, nonce, kRoom, ad)
	copy(wrap[NonceSize:], out)
	return wrap[:], nil
}

func OpenWrap(isk, wrap []byte) (kRoom []byte, err error) {
	// first, derive the key for the wrap
	wrapKey, err := hkdf.Expand(sha256.New, isk, wrapLabel, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate wrap key: %v", err)
	}

	// now for unsealing the wrap and (assuming the isk is correct) getting the kRoom
	aead, err := chacha20poly1305.NewX(wrapKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AEAD: %v", err)
	}

	nonce := wrap[:NonceSize]
	ad := []byte{byte(KindHandshake)}
	kRoom, err = aead.Open(nil, nonce, wrap[NonceSize:], ad)

	if err != nil {
		return nil, fmt.Errorf("failed to open wrap: %v", err)
	}
	return
}

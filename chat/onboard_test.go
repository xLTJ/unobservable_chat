package chat

import (
	"bytes"
	"crypto/rand"
	"testing"

	"filippo.io/cpace"
)

// randomBytes returns n bytes from crypto/rand, standing in for real CPace output or a key.
func randomBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

// throughWire encodes f and decodes it again, like sending it to the relay and back.
func throughWire(t *testing.T, f Frame) Frame {
	t.Helper()
	c, err := f.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	f, err = Decode(c)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	return f
}

// onboard runs one join the way SPEC §7.4 does it, both sides in one process, every
// message through a frame and the wire format. It returns the K_room the joiner got
// out of the wrap, or OpenWrap's error.
func onboard(t *testing.T, joinerPassword, memberPassword string, kRoom []byte) ([]byte, error) {
	t.Helper()
	joinerPw, err := NormalisePassword(joinerPassword)
	if err != nil {
		t.Fatalf("joiner NormalisePassword: %v", err)
	}
	memberPw, err := NormalisePassword(memberPassword)
	if err != nil {
		t.Fatalf("member NormalisePassword: %v", err)
	}

	// joiner: msgA
	msgA, state, err := cpace.Start(joinerPw, CPaceContext())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	f := throughWire(t, MakeMsgAFrame(msgA))

	// member: parse, exchange, wrap, reply
	h, err := ParseHandshake(f)
	if err != nil || h.Subtype != SubtypeMsgA {
		t.Fatalf("member parsing msgA: sub-type %#x, err %v", h.Subtype, err)
	}
	msgB, memberISK, err := cpace.Exchange(memberPw, CPaceContext(), h.MsgA)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	wrap, err := SealWrap(memberISK, kRoom)
	if err != nil {
		t.Fatalf("SealWrap: %v", err)
	}
	if len(wrap) != WrapSize {
		t.Fatalf("SealWrap returned %d bytes, want WrapSize %d", len(wrap), WrapSize)
	}
	f = throughWire(t, MakeReplyFrame(h.MsgA[:SidSize], msgB, wrap))

	// joiner: parse, match the sid, finish, unwrap
	h, err = ParseHandshake(f)
	if err != nil || h.Subtype != SubtypeReply {
		t.Fatalf("joiner parsing reply: sub-type %#x, err %v", h.Subtype, err)
	}
	if !bytes.Equal(h.Sid, msgA[:SidSize]) {
		t.Fatal("the reply's sid is not the joiner's")
	}
	joinerISK, err := state.Finish(h.MsgB)
	if err != nil {
		t.Fatalf("Finish: %v", err)
	}
	return OpenWrap(joinerISK, h.Wrap)
}

func TestHandshakeSizes(t *testing.T) {
	// SPEC §3.5
	for _, tc := range []struct {
		name      string
		got, want int
	}{
		{"SidSize", SidSize, 16},
		{"MsgASize", MsgASize, 48},
		{"MsgBSize", MsgBSize, 32},
		{"WrapSize", WrapSize, 72},
	} {
		if tc.got != tc.want {
			t.Errorf("%s = %d, want %d", tc.name, tc.got, tc.want)
		}
	}

	// both handshake cells must fit one body: 1 + 48 and 1 + 16 + 32 + 72
	if n := SubtypeSize + MsgASize; n != 49 {
		t.Errorf("msgA cell uses %d body bytes, want 49", n)
	}
	if n := SubtypeSize + SidSize + MsgBSize + WrapSize; n != 121 || n > BodySize {
		t.Errorf("reply cell uses %d body bytes, want 121 (at most BodySize %d)", n, BodySize)
	}
}

func TestHandshakeSizesMatchLibrary(t *testing.T) {
	// the library exports no size constants, so check ours against what it actually returns
	ci := cpace.NewContextInfo("", "", nil)
	msgA, _, err := cpace.Start("password", ci)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if len(msgA) != MsgASize {
		t.Errorf("cpace.Start returned %d bytes, MsgASize is %d", len(msgA), MsgASize)
	}

	msgB, isk, err := cpace.Exchange("password", ci, msgA)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if len(msgB) != MsgBSize {
		t.Errorf("cpace.Exchange returned a %d-byte msgB, MsgBSize is %d", len(msgB), MsgBSize)
	}
	if len(isk) != 32 {
		t.Errorf("ISK is %d bytes, want 32", len(isk))
	}
}

func TestSubtypeValues(t *testing.T) {
	// wire values fixed by SPEC §3.5; 0x00 is not a valid sub-type
	if SubtypeMsgA != 0x01 {
		t.Errorf("SubtypeMsgA = %#x, want 0x01", SubtypeMsgA)
	}
	if SubtypeReply != 0x02 {
		t.Errorf("SubtypeReply = %#x, want 0x02", SubtypeReply)
	}
}

func TestNormalisePassword(t *testing.T) {
	// PRECIS OpaqueString (RFC 8265, D-069): the same password must give the same bytes
	for _, tc := range []struct {
		name, in, want string
	}{
		{"ascii unchanged", "correct horse battery staple", "correct horse battery staple"},
		{"case kept", "Tulip", "Tulip"},
		{"composed é unchanged", "caf\u00e9", "caf\u00e9"},
		{"decomposed é composed (NFC)", "cafe\u0301", "caf\u00e9"},
		{"non-breaking space to space", "a\u00a0b", "a b"},
	} {
		got, err := NormalisePassword(tc.in)
		if err != nil {
			t.Errorf("%s: error %v", tc.name, err)
			continue
		}
		if got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestNormalisePasswordRejects(t *testing.T) {
	for name, in := range map[string]string{
		"empty":             "",
		"control character": "pass\tword",
	} {
		if _, err := NormalisePassword(in); err == nil {
			t.Errorf("%s: accepted %q", name, in)
		}
	}
}

func TestControlRoundtrip(t *testing.T) {
	for earlier := 0; earlier < RoomCap; earlier++ {
		f := MakeControlFrame(earlier)
		if f.Kind != KindRelayControl {
			t.Fatalf("earlier=%d: kind = %d, want %d", earlier, f.Kind, KindRelayControl)
		}

		// through the wire format: SPEC §3.6 is 0x04 | earlier | zeros
		c, err := f.Encode()
		if err != nil {
			t.Fatalf("earlier=%d: Encode: %v", earlier, err)
		}
		if c[0] != 0x04 || c[1] != byte(earlier) {
			t.Errorf("earlier=%d: cell starts % x, want 04 %02x", earlier, c[:2], earlier)
		}
		if !bytes.Equal(c[2:], make([]byte, CellSize-2)) {
			t.Errorf("earlier=%d: bytes after earlier are not all zero", earlier)
		}

		f, err = Decode(c)
		if err != nil {
			t.Fatalf("earlier=%d: Decode: %v", earlier, err)
		}
		got, err := ParseControl(f)
		if err != nil {
			t.Fatalf("earlier=%d: ParseControl: %v", earlier, err)
		}
		if got != earlier {
			t.Errorf("ParseControl = %d, want %d", got, earlier)
		}
	}
}

func TestParseControlRejectsOtherKinds(t *testing.T) {
	for _, k := range []Kind{KindData, KindHandshake} {
		if _, err := ParseControl(Frame{Kind: k}); err == nil {
			t.Errorf("ParseControl accepted a frame of kind %d", k)
		}
	}
}

func TestMsgARoundtrip(t *testing.T) {
	msgA := randomBytes(MsgASize)

	f := MakeMsgAFrame(msgA)
	if f.Kind != KindHandshake {
		t.Fatalf("kind = %d, want %d", f.Kind, KindHandshake)
	}

	// SPEC §3.5: 0x01 | msgA (48) | zeros
	if f.Body[0] != byte(SubtypeMsgA) {
		t.Errorf("sub-type byte = %#x, want %#x", f.Body[0], SubtypeMsgA)
	}
	if !bytes.Equal(f.Body[1:1+MsgASize], msgA) {
		t.Error("msgA is not at body bytes [1:49]")
	}
	if !bytes.Equal(f.Body[1+MsgASize:], make([]byte, BodySize-1-MsgASize)) {
		t.Error("bytes after msgA are not all zero")
	}

	h, err := ParseHandshake(throughWire(t, f))
	if err != nil {
		t.Fatalf("ParseHandshake: %v", err)
	}
	if h.Subtype != SubtypeMsgA {
		t.Errorf("parsed sub-type = %#x, want msgA", h.Subtype)
	}
	if !bytes.Equal(h.MsgA, msgA) {
		t.Error("parsed msgA differs from the one sent")
	}
}

func TestReplyRoundtrip(t *testing.T) {
	sid := randomBytes(SidSize)
	msgB := randomBytes(MsgBSize)
	wrap := randomBytes(WrapSize)

	f := MakeReplyFrame(sid, msgB, wrap)
	if f.Kind != KindHandshake {
		t.Fatalf("kind = %d, want %d", f.Kind, KindHandshake)
	}

	// SPEC §3.5: 0x02 | sid (16) | msgB (32) | wrap (72) | zeros (356)
	end := SubtypeSize + SidSize + MsgBSize + WrapSize
	want := append([]byte{byte(SubtypeReply)}, sid...)
	want = append(want, msgB...)
	want = append(want, wrap...)
	if !bytes.Equal(f.Body[:end], want) {
		t.Error("reply fields are not at the offsets in SPEC §3.5")
	}
	if !bytes.Equal(f.Body[end:], make([]byte, BodySize-end)) {
		t.Error("bytes after the wrap are not all zero")
	}

	h, err := ParseHandshake(throughWire(t, f))
	if err != nil {
		t.Fatalf("ParseHandshake: %v", err)
	}
	if h.Subtype != SubtypeReply {
		t.Errorf("parsed sub-type = %#x, want reply", h.Subtype)
	}
	if !bytes.Equal(h.Sid, sid) || !bytes.Equal(h.MsgB, msgB) || !bytes.Equal(h.Wrap, wrap) {
		t.Error("parsed sid, msgB or wrap differs from what was sent")
	}
}

func TestParseHandshakeRejectsUnknownSubtype(t *testing.T) {
	// SPEC §3.5: any other sub-type is dropped and logged, so parsing must fail
	for _, st := range []byte{0x00, 0x03, 0xff} {
		f := Frame{Kind: KindHandshake}
		f.Body[0] = st
		if _, err := ParseHandshake(f); err == nil {
			t.Errorf("ParseHandshake accepted sub-type %#x", st)
		}
	}
}

func TestOnboardSamePassword(t *testing.T) {
	kRoom := randomBytes(32)
	got, err := onboard(t, "correct horse battery staple", "correct horse battery staple", kRoom)
	if err != nil {
		t.Fatalf("OpenWrap: %v", err)
	}
	if !bytes.Equal(got, kRoom) {
		t.Error("the joiner got a different K_room")
	}
}

func TestOnboardEquivalentPasswords(t *testing.T) {
	// "é" typed as one code point and as e + combining accent must onboard (D-069)
	kRoom := randomBytes(32)
	got, err := onboard(t, "cafe\u0301", "caf\u00e9", kRoom)
	if err != nil {
		t.Fatalf("OpenWrap: %v", err)
	}
	if !bytes.Equal(got, kRoom) {
		t.Error("the joiner got a different K_room")
	}
}

func TestCPaceContextStable(t *testing.T) {
	// both sides build their own context, so two calls must agree byte for byte
	msgA, state, err := cpace.Start("pw", CPaceContext())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	msgB, memberISK, err := cpace.Exchange("pw", CPaceContext(), msgA)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	joinerISK, err := state.Finish(msgB)
	if err != nil {
		t.Fatalf("Finish: %v", err)
	}
	if !bytes.Equal(joinerISK, memberISK) {
		t.Error("same password, two CPaceContext() calls: the keys differ")
	}
}

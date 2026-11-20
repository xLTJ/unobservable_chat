package main

import (
	"bytes"
	"log"
	"slices"
	"strings"
	"testing"

	"github.com/xLTJ/unobservable_chat/chat"
)

// fragment builds a message plaintext as the receive loop gets it from OpenData.
func fragment(sender byte, msg uint16, index byte, last bool, payload string) chat.Plaintext {
	return chat.Plaintext{
		Flag:          chat.FlagMessage,
		Payload:       []byte(payload),
		Sender:        [4]byte{sender, sender, sender, sender},
		MsgNum:        msg,
		FragmentIndex: index,
		Last:          last,
	}
}

// feed runs the fragments through reassembly in order and returns the bodies it delivered.
func feed(messages map[[4]byte]*inProgress, fragments ...chat.Plaintext) []string {
	var delivered []string
	for _, f := range fragments {
		if body := reassembleMessage(messages, f); body != nil {
			delivered = append(delivered, string(body))
		}
	}
	return delivered
}

// captureLog sends the log package's output to a buffer for the rest of the test.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(previous) })
	return &buf
}

func checkDelivered(t *testing.T, got, want []string) {
	t.Helper()
	if !slices.Equal(got, want) {
		t.Errorf("delivered %q, want %q", got, want)
	}
}

func TestReassembleOneCell(t *testing.T) {
	messages := make(map[[4]byte]*inProgress)
	got := feed(messages, fragment(1, 0, 0, true, "hello"))
	checkDelivered(t, got, []string{"hello"})
}

func TestReassembleFragments(t *testing.T) {
	messages := make(map[[4]byte]*inProgress)

	// nothing comes out before the last fragment
	got := feed(messages,
		fragment(1, 0, 0, false, "aa"),
		fragment(1, 0, 1, false, "bb"),
		fragment(1, 0, 2, false, "cc"),
		fragment(1, 0, 3, false, "dd"),
	)
	checkDelivered(t, got, nil)

	// then the whole message, in order
	got = feed(messages, fragment(1, 0, 4, true, "e"))
	checkDelivered(t, got, []string{"aabbccdde"})
}

func TestReassembleLostMiddle(t *testing.T) {
	// SPEC §3.4: a gap drops the whole message, never part of it, and the next message still arrives
	logs := captureLog(t)
	messages := make(map[[4]byte]*inProgress)
	got := feed(messages,
		fragment(1, 0, 0, false, "aa"),
		fragment(1, 0, 1, false, "bb"),
		// fragment 2 lost
		fragment(1, 0, 3, false, "dd"),
		fragment(1, 0, 4, true, "e"),
		fragment(1, 1, 0, true, "next"),
	)
	checkDelivered(t, got, []string{"next"})
	if logs.Len() == 0 {
		t.Error("the dropped message was not logged")
	}
}

func TestReassembleLostTail(t *testing.T) {
	// frag 0 while a message is in progress: the old one is dropped and the new one starts.
	// a one-cell message right after a lost tail must still come out
	logs := captureLog(t)
	messages := make(map[[4]byte]*inProgress)
	got := feed(messages,
		fragment(1, 0, 0, false, "aa"),
		fragment(1, 0, 1, false, "bb"),
		// fragment 2, the last, lost
		fragment(1, 1, 0, true, "next"),
	)
	checkDelivered(t, got, []string{"next"})
	if logs.Len() == 0 {
		t.Error("the dropped message was not logged")
	}

	// and the same for a message of several fragments
	got = feed(messages,
		fragment(1, 2, 0, false, "aa"),
		// fragment 1, the last, lost
		fragment(1, 3, 0, false, "x"),
		fragment(1, 3, 1, true, "y"),
	)
	checkDelivered(t, got, []string{"xy"})
}

func TestReassembleWrongMsgNum(t *testing.T) {
	logs := captureLog(t)
	messages := make(map[[4]byte]*inProgress)

	// the right next index, but from another message: a loss that spans two messages (SPEC §3.4)
	got := feed(messages,
		fragment(1, 0, 0, false, "aa"),
		fragment(1, 5, 1, true, "bb"),
	)
	checkDelivered(t, got, nil)
	if logs.Len() == 0 {
		t.Error("the dropped message was not logged")
	}
}

func TestReassembleNoStart(t *testing.T) {
	logs := captureLog(t)
	messages := make(map[[4]byte]*inProgress)

	// a fragment after the first with nothing in progress, also right after a completed message
	got := feed(messages,
		fragment(1, 0, 1, true, "orphan"),
		fragment(1, 1, 0, true, "a"),
		fragment(1, 2, 1, true, "b"),
	)
	checkDelivered(t, got, []string{"a"})
	if logs.Len() == 0 {
		t.Error("the dropped fragments were not logged")
	}
}

func TestReassembleInterleaved(t *testing.T) {
	// several members send fragments in the same ticks; each sender is put together on its own
	messages := make(map[[4]byte]*inProgress)
	got := feed(messages,
		fragment(1, 0, 0, false, "a1"),
		fragment(2, 0, 0, false, "b1"),
		fragment(1, 0, 1, false, "a2"),
		fragment(2, 0, 1, true, "b2"),
		fragment(1, 0, 2, true, "a3"),
	)
	checkDelivered(t, got, []string{"b1b2", "a1a2a3"})
}

func TestReassembleFragmentLimit(t *testing.T) {
	// SPEC §3.4: at most 10 fragments
	messages := make(map[[4]byte]*inProgress)

	var ten []chat.Plaintext
	for i := range 10 {
		ten = append(ten, fragment(1, 0, byte(i), i == 9, "x"))
	}
	checkDelivered(t, feed(messages, ten...), []string{strings.Repeat("x", 10)})

	logs := captureLog(t)
	var eleven []chat.Plaintext
	for i := range 11 {
		eleven = append(eleven, fragment(1, 1, byte(i), i == 10, "x"))
	}
	checkDelivered(t, feed(messages, eleven...), nil)
	if logs.Len() == 0 {
		t.Error("the 11-fragment message was not logged")
	}
}

func TestReassembleSizeLimit(t *testing.T) {
	// SPEC §3.4: a body grows to at most 4129 bytes, 1 + NAME_MAX + MAX_MESSAGE
	maxBody := 1 + chat.DisplayNameMaxLen + chat.MessageMaxLen
	full := strings.Repeat("x", chat.PayloadMaxSize)
	messages := make(map[[4]byte]*inProgress)

	// exactly the largest body: 9 full fragments and a shorter last one
	var largest []chat.Plaintext
	for i := range 9 {
		largest = append(largest, fragment(1, 0, byte(i), false, full))
	}
	largest = append(largest, fragment(1, 0, 9, true, strings.Repeat("x", maxBody-9*chat.PayloadMaxSize)))
	got := feed(messages, largest...)
	if len(got) != 1 || len(got[0]) != maxBody {
		t.Errorf("the largest body: delivered %d messages, want 1 of %d bytes", len(got), maxBody)
	}

	// 10 full fragments are within the fragment limit but over the size limit
	logs := captureLog(t)
	var tooBig []chat.Plaintext
	for i := range 10 {
		tooBig = append(tooBig, fragment(1, 1, byte(i), i == 9, full))
	}
	if got := feed(messages, tooBig...); len(got) != 0 {
		t.Errorf("a %d-byte body was delivered, want it dropped", 10*chat.PayloadMaxSize)
	}
	if logs.Len() == 0 {
		t.Error("the oversized message was not logged")
	}
}

func TestReassembleClearsState(t *testing.T) {
	// nothing in progress means no entry, so a sender that leaves leaves nothing behind
	_ = captureLog(t)
	messages := make(map[[4]byte]*inProgress)

	feed(messages, fragment(1, 0, 0, true, "done"))
	if len(messages) != 0 {
		t.Errorf("after a completed message: %d entries, want 0", len(messages))
	}

	feed(messages, fragment(1, 1, 0, false, "aa"), fragment(1, 1, 2, true, "cc"))
	if len(messages) != 0 {
		t.Errorf("after a dropped message: %d entries, want 0", len(messages))
	}
}

package main

import (
	"crypto/rand"
	"fmt"
	"time"

	"filippo.io/cpace"
	"github.com/xLTJ/unobservable_chat/chat"
	"golang.org/x/crypto/chacha20poly1305"
)

// handleOnboarding handles the synchronous part of the onboarding process
func (c *client) handleOnboarding() error {
	// wait for onboard cell and open decode it
	cell, err := chat.ReadCell(c.conn)
	if err != nil {
		return fmt.Errorf("failed to read from server: %v", err)
	}
	frame, err := chat.Decode(cell)
	if err != nil {
		return fmt.Errorf("failed to decode onboard frame: %v", err)
	}

	// check if kind is relay control
	if frame.Kind != chat.KindRelayControl {
		return fmt.Errorf("expected first cell to be a control cell, got %d", frame.Kind)
	}

	// parse control frame to get earlier
	earlier, err := chat.ParseControl(frame)
	if err != nil {
		return fmt.Errorf("failed to parse control frame: %v", err)
	}

	// next steps depend on earlier
	switch {
	case earlier > chat.RoomCap-1:
		// room is full, exit
		return fmt.Errorf("room is full")
	case earlier == 0:
		// room is empty so this user is a founder. just generate new kRoom and AEAD and carry on
		kRoom := make([]byte, 32)
		_, _ = rand.Read(kRoom)
		c.kRoom = kRoom

		aead, err := chacha20poly1305.NewX(c.kRoom)
		if err != nil {
			return fmt.Errorf("failed to create AEAD: %v", err)
		}
		c.keyReadyChan <- aead
		c.aead = aead
	default:
		// otherwise, this user is a joiner

		// initiate a new PAKE exchange, create msgA and the cpace state
		msgA, state, err := cpace.Start(c.password, c.cpaceContext)
		if err != nil {
			return fmt.Errorf("failed to start CPace: %v", err)
		}
		c.cpaceState = state

		// set the sid from the first bytes of msgA
		c.sid = msgA[:chat.SidSize]

		// send msgA to handshake channel, to be handled later
		msgAFrame := chat.MakeMsgAFrame(msgA)
		c.handshakeOutChan <- msgAFrame

		// set a deadline for the joiner to wait for the reply
		err = c.conn.SetReadDeadline(time.Now().Add(chat.Tick * chat.JoinTimeout))
		if err != nil {
			return fmt.Errorf("failed to set deadline: %v", err)
		}
	}

	return nil
}

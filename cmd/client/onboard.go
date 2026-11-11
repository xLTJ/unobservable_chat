package main

import (
	"crypto/rand"
	"fmt"
	"log"
	"time"

	"filippo.io/cpace"
	"github.com/xLTJ/unobservable_chat/chat"
	"golang.org/x/crypto/chacha20poly1305"
)

// handleOnboarding handles the synchronous part of the onboarding process
func (c *client) handleOnboarding() error {
	log.Println("onboarding...")

	// send hello frame first. send loop isn't running yet, so we have to send it manually
	helloFrame, err := chat.MakeHelloFrame(chat.ModePrivate, c.roomName)
	if err != nil {
		return fmt.Errorf("failed to make hello frame: %v", err)
	}
	helloCell, err := helloFrame.Encode()
	if err != nil {
		return fmt.Errorf("failed to encode hello frame: %v", err)
	}
	_, err = c.conn.Write(helloCell[:])
	if err != nil {
		return fmt.Errorf("failed to write hello frame to server: %v", err)
	}
	log.Println("sent hello frame")
	log.Println("waiting for onboard cell...")

	// then wait for onboard cell and decode it
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
	log.Println("received relay control")

	// parse control frame to get earlier
	earlier, err := chat.ParseControl(frame)
	if err != nil {
		return fmt.Errorf("failed to parse control frame: %v", err)
	}

	// next steps depend on earlier
	switch {
	case earlier > chat.RoomCap:
		return fmt.Errorf("invalid earlier: %d. This should never happen, and is a bug in the relay", earlier)
	case earlier == chat.RoomCap:
		// room is full, exit
		return fmt.Errorf("room is full")
	case earlier == 0:
		// room is empty so this user is a founder. just generate new kRoom and AEAD and carry on
		log.Println("room empty, creating a new room...")

		kRoom := make([]byte, 32)
		_, _ = rand.Read(kRoom)
		c.kRoom = kRoom

		aead, err := chacha20poly1305.NewX(c.kRoom)
		if err != nil {
			return fmt.Errorf("failed to create AEAD: %v", err)
		}
		c.keyReadyChan <- aead
		c.aead = aead
		log.Println("room successfully created")
	default:
		// otherwise, this user is a joiner
		log.Println("room exists, joining...")

		// initiate a new PAKE exchange, create msgA and the cpace state
		msgA, state, err := cpace.Start(c.password, c.cpaceContext)
		if err != nil {
			return fmt.Errorf("failed to start CPace: %v", err)
		}
		c.cpaceState = state

		// set the sid from the first bytes of msgA
		c.sid = msgA[:chat.SidSize]

		// send msgA to handshake channel, to be handled later
		log.Println("initiating handshake...")
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

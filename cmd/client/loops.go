package main

import (
	"bufio"
	"bytes"
	"crypto/cipher"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"filippo.io/cpace"
	"github.com/xLTJ/unobservable_chat/chat"
	"golang.org/x/crypto/chacha20poly1305"
)

func (c *client) receive() error {
	for {
		cell, err := chat.ReadCell(c.conn)
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return fmt.Errorf("connection timed out")
		}
		if err != nil {
			return fmt.Errorf("failed to read from server: %v", err)
		}

		// decode frame
		frame, err := chat.Decode(cell)
		if err != nil {
			// just drop invalid frames and continue
			// log.Println("Failed to decode cell: ", err) // debug
			continue
		}

		switch frame.Kind {
		case chat.KindData:
			c.handleData(frame)

		case chat.KindHandshake:
			if err := c.handleHandshake(frame); err != nil {
				return fmt.Errorf("failed to handle handshake: %v", err)
			}
		case chat.KindRelayControl:
			// the client should never recieve a relay control frame from the relay after the first one, this is a bug
			log.Println("unexpected relay control frame, this should never happen")
			continue
		default:
			log.Println("unexpected frame kind: ", frame.Kind)
			continue
		}
	}
}

func (c *client) handleData(frame chat.Frame) {
	// no aead means that the client has not yet joined a room, ignore data frames
	if c.aead == nil {
		return
	}

	// open data to access plaintext
	plaintext, err := chat.OpenData(c.aead, frame)
	if errors.Is(err, chat.ErrOpen) {
		return // ErrOpen drops silently if the frame is tampered with
	}
	if err != nil {
		log.Println("failed to open frame: ", err)
		return
	}

	// ignore dummies
	if plaintext.Flag == chat.FlagDummy {
		return
	}

	fmt.Println(string(plaintext.Payload))
}

func (c *client) handleHandshake(frame chat.Frame) error {
	handshake, err := chat.ParseHandshake(frame)
	if err != nil {
		log.Println("failed to parse handshake: ", err)
		return nil
	}

	if c.kRoom != nil {
		// client is a member, check if subtype is correct, then exchange, wrap, reply
		if handshake.Subtype != chat.SubtypeMsgA {
			// normal traffic, ignore
			return nil
		}

		msgB, memberISK, err := cpace.Exchange(c.password, c.cpaceContext, handshake.MsgA)
		if err != nil {
			log.Println("failed to exchange: ", err)
			return nil
		}
		wrap, err := chat.SealWrap(memberISK, c.kRoom)
		if err != nil {
			log.Println("failed to seal wrap: ", err)
			return nil
		}

		select {
		case c.handshakeOutChan <- chat.MakeReplyFrame(handshake.Sid, msgB, wrap):
		default:
			log.Println("failed to send reply frame: channel is full, dropping frame")
		}
	} else {
		// otherwise client is a joiner, check subtype, see if sid matches, then finish and unwrap
		if handshake.Subtype != chat.SubtypeReply {
			// normal traffic, ignore
			return nil
		}

		if !bytes.Equal(handshake.Sid, c.sid) {
			// sid does not match, this is normal when two joiners overlap, just ignore
			return nil
		}
		joinerISK, err := c.cpaceState.Finish(handshake.MsgB)
		if err != nil {
			return fmt.Errorf("failed to finish CPace: %v", err)
		}
		c.cpaceState = nil // no longer needed

		kRoom, err := chat.OpenWrap(joinerISK, handshake.Wrap)
		if len(kRoom) != 32 {
			return fmt.Errorf("failed to open wrap: wrong length")
		}
		if err != nil {
			return fmt.Errorf("refused: wrong password")
		}
		c.kRoom = kRoom

		// create AEAD and set it
		aead, err := chacha20poly1305.NewX(kRoom)
		if err != nil {
			return fmt.Errorf("failed to create AEAD: %v", err)
		}
		c.keyReadyChan <- aead
		c.aead = aead

		// now we can also remove the deadline
		_ = c.conn.SetReadDeadline(time.Time{})
	}
	return nil
}

func (c *client) send() error {
	// local aead copy, used to avoid a race condition. aead is only set once anyway, so this is fine
	var aeadCopy cipher.AEAD

	ticker := time.NewTicker(chat.Tick)
	defer ticker.Stop()

	for range ticker.C {
		// if a key is ready, set it and proceed with the tick
		select {
		case aead := <-c.keyReadyChan:
			aeadCopy = aead
		default:
		}

		// if there is a handshake frame waiting, send it and finish the tick
		select {
		case frame := <-c.handshakeOutChan:
			handshakeCell, err := frame.Encode()
			if err != nil {
				return fmt.Errorf("failed to encode handshake frame: %v", err)
			}
			_, err = c.conn.Write(handshakeCell[:])
			if err != nil {
				return fmt.Errorf("failed to write handshake frame to server: %v", err)
			}
			continue
		default:
		}

		// if no key is set yet, send filler frame for this tick
		if c.kRoom == nil {
			fillerFrame := chat.MakeFillerFrame()
			fillerCell, err := fillerFrame.Encode()
			if err != nil {
				return fmt.Errorf("failed to encode filler frame: %v", err)
			}
			_, err = c.conn.Write(fillerCell[:])
			if err != nil {
				return fmt.Errorf("failed to write filler frame to server: %v", err)
			}
			continue
		}

		// if we reach this point, the client is handling normal traffic

		// if a payload is queued, create a message from it, otherwise create a dummy message
		var plaintext chat.Plaintext
		select {
		case payload := <-c.payloadSendChan:
			plaintext = chat.Plaintext{
				Flag:    chat.FlagMessage,
				Payload: payload,
			}
		default:
			plaintext.Flag = chat.FlagDummy
		}

		// seal data and encode it into a cell
		frame, err := chat.SealData(aeadCopy, plaintext)
		if err != nil {
			return fmt.Errorf("failed to seal frame: %v", err)
		}
		cell, err := frame.Encode()
		if err != nil {
			return fmt.Errorf("failed to encode frame: %v", err)
		}

		// and send it
		_, err = c.conn.Write(cell[:])
		if err != nil {
			return fmt.Errorf("failed to write to server: %v", err)
		}
	}

	return nil
}

func (c *client) handleInput() error {
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		payload := []byte(scanner.Text())

		// until fragmentation is implemented, messages cannot exceed the size of one payload
		if len(payload) > chat.PayloadMaxSize {
			log.Println("error: message too long")
			continue
		}

		// skip empty messages
		if len(payload) == 0 {
			continue
		}

		c.payloadSendChan <- payload
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("failed to read from stdin: %v", err)
	}

	// block until client exits
	select {}
}

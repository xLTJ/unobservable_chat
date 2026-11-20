package main

import (
	"bufio"
	"bytes"
	"crypto/cipher"
	"crypto/rand"
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
			return fmt.Errorf("no reply from the room")
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

	reassembledMessage := reassembleMessage(c.messagesInProgress, plaintext)
	if reassembledMessage == nil {
		// message is not yet ready, nothing to print
		return
	}

	senderName, text, err := chat.ParseBody(reassembledMessage)
	if err != nil {
		log.Println("failed to parse body: ", err)
		return
	}
	fmt.Printf("%s: %s\n", senderName, text)
}

// reassembleMessage reassembles the fragments of a message into a single message.
// it returns the reassembled message, or nil if the message is incomplete.
func reassembleMessage(messagesInProgress map[[4]byte]*inProgress, p chat.Plaintext) []byte {
	currentMessage, ok := messagesInProgress[p.Sender]

	if p.FragmentIndex == 0 {
		// no message in progress
		if ok {
			// if the fragment index is 0, there should be no message in progress. overwrite it and continue
			log.Println("received a fragment with index 0, but there is a message in progress. Dropping message in progress.")
		}
		messagesInProgress[p.Sender] = &inProgress{
			msgNum:            p.MsgNum,
			nextFragmentIndex: 0, // gets incremented later
			body:              make([]byte, 0, chat.MessageMaxLen),
		}
		currentMessage = messagesInProgress[p.Sender]
	} else {
		// there is a message in progress
		if !ok {
			// if the fragment index is not 0, there should be a message in progress. drop the message
			log.Println("received a fragment with index != 0, but there is no message in progress. Dropping...")
			return nil
		}
		// does the fragment index match the expected one?
		if currentMessage.nextFragmentIndex != p.FragmentIndex {
			log.Println("received a fragment with an unexpected index. Dropping...")
			delete(messagesInProgress, p.Sender)
			return nil
		}
		// does the message number match the expected one?
		if currentMessage.msgNum != p.MsgNum {
			log.Println("received a fragment with an unexpected message number. Dropping...")
			delete(messagesInProgress, p.Sender)
			return nil
		}
	}

	// add the payload to the message body, check if the message is too long
	currentMessage.body = append(currentMessage.body, p.Payload...)
	if len(currentMessage.body) > 1+chat.DisplayNameMaxLen+chat.MessageMaxLen {
		log.Println("received a message that is too long. Dropping...")
		delete(messagesInProgress, p.Sender)
		return nil
	}

	if !p.Last {
		// if this is not the last fragment, increment the fragment index and return
		currentMessage.nextFragmentIndex++

		// check if the next fragment would exceed the max
		if currentMessage.nextFragmentIndex >= chat.FragmentsMax {
			log.Println("received a message that would have too many fragments. Dropping...")
			delete(messagesInProgress, p.Sender)
		}

		return nil
	}

	// return the finished message and remove the message from the map
	delete(messagesInProgress, p.Sender)
	return currentMessage.body
}

func (c *client) handleHandshake(frame chat.Frame) error {
	handshake, err := chat.ParseHandshake(frame)
	if err != nil {
		log.Println("failed to parse handshake: ", err)
		return nil
	}

	if c.kRoom != nil {
		// client is a member, check if subtype is correct, then exchange, wrap, reply
		c.answerJoin(handshake)
	} else {
		// otherwise client is a joiner, check subtype, see if sid matches, then finish and unwrap
		err := c.finishJoin(handshake)
		if err != nil {
			return fmt.Errorf("failed to finish join: %v", err)
		}
	}
	return nil
}

func (c *client) answerJoin(handshake chat.Handshake) {
	if handshake.Subtype != chat.SubtypeMsgA {
		// normal traffic, ignore
		return
	}

	log.Println("user requested to join, exchanging...")
	msgB, memberISK, err := cpace.Exchange(c.password, c.cpaceContext, handshake.MsgA)
	if err != nil {
		log.Println("failed to exchange: ", err)
		return
	}
	wrap, err := chat.SealWrap(memberISK, c.kRoom)
	if err != nil {
		log.Println("failed to seal wrap: ", err)
		return
	}

	select {
	case c.handshakeOutChan <- chat.MakeReplyFrame(handshake.Sid, msgB, wrap):
		log.Println("reply sent")
	default:
		log.Println("failed to send reply frame: channel is full, dropping frame")
	}
}

func (c *client) finishJoin(handshake chat.Handshake) error {
	if handshake.Subtype != chat.SubtypeReply {
		// normal traffic, ignore
		return nil
	}

	if !bytes.Equal(handshake.Sid, c.sid) {
		// sid does not match, this is normal when two joiners overlap, just ignore
		return nil
	}
	log.Println("reply received, joining room...")
	joinerISK, err := c.cpaceState.Finish(handshake.MsgB)
	if err != nil {
		return fmt.Errorf("failed to finish CPace: %v", err)
	}
	c.cpaceState = nil // no longer needed

	kRoom, err := chat.OpenWrap(joinerISK, handshake.Wrap)
	if err != nil {
		return fmt.Errorf("wrong password, or the room name is in use with a different password")
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
	log.Println("room successfully joined")
	return nil
}

func (c *client) send() error {
	// local aead copy, used to avoid a race condition. aead is only set once anyway, so this is fine
	var aeadCopy cipher.AEAD

	// set up everything needed across ticks
	var senderId [4]byte
	_, _ = rand.Read(senderId[:])

	msgNum := uint16(0)
	fragmentIndex := 0
	var payloadPieces [][]byte

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
		if aeadCopy == nil {
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
		var plaintext chat.Plaintext

		// if there are no ready pieces, check if there are any new payloads queued
		if len(payloadPieces) == 0 {
			select {
			case payload := <-c.payloadSendChan:
				// if there is a payload, build a body and split it into pieces
				body, err := chat.BuildBody(c.name, string(payload))
				if err != nil {
					log.Println("error: failed to build body: ", err)
				}
				payloadPieces = chat.SplitBody(body)
			default:
			}

		}

		// if there are ready pieces, ready a message from them
		if len(payloadPieces) > 0 {
			plaintext = chat.Plaintext{
				Flag:          chat.FlagMessage,
				Payload:       payloadPieces[fragmentIndex],
				FragmentIndex: byte(fragmentIndex),
				Sender:        senderId,
				MsgNum:        msgNum,
			}

			// if this is the last piece, set the last flag and reset the payloadPieces slice
			if fragmentIndex == len(payloadPieces)-1 {
				plaintext.Last = true
				fragmentIndex = 0
				payloadPieces = nil
				msgNum++
			} else {
				fragmentIndex++
			}
		} else {
			// if there are no ready pieces, ready a dummy message
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

		if len(payload) > chat.MessageMaxLen {
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

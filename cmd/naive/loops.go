package main

import (
	"bufio"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/xLTJ/unobservable_chat/chat"
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
			log.Println("this version does not use handshakes")
			continue
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

package main

import (
	"bufio"
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"filippo.io/cpace"
	"github.com/xLTJ/unobservable_chat/chat"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/net/proxy"
)

type client struct {
	conn            net.Conn
	name            string
	payloadSendChan chan []byte

	aead     cipher.AEAD
	kRoom    []byte
	password string

	sid              []byte
	cpaceState       *cpace.State
	cpaceContext     *cpace.ContextInfo
	handshakeOutChan chan chat.Frame  // channel for outgoing handshake messages
	keyReadyChan     chan cipher.AEAD // channel to pass the key to the send goroutine, avoiding a race condition
}

const payloadChanSize = 100

// flags
var name = flag.String("name", "Anonymous", "name to display")
var relayHost = flag.String("relay", "127.0.0.1", "host of relay")
var socksAddress = flag.String("socks", "", "address of socks proxy, empty for direct") // check params for which to use

func main() {
	// do whatever here idk
	flag.Parse()

	// run client, log any exit errors
	err := run()
	if err != nil {
		log.Fatal(err)
	}
}

func run() error {
	// before anything else, get the password from the environment. no password = instant death
	password := os.Getenv("UC_PASSWORD")
	if password == "" {
		return fmt.Errorf("environment variable UC_PASSWORD is not set")
	}
	password, err := chat.NormalisePassword(password)
	if err != nil {
		return fmt.Errorf("failed to normalise password: %v", err)
	}

	var connection net.Conn

	// if socks is empty, connect directly to relay, otherwise connect through socks
	if *socksAddress == "" {
		log.Println("connecting to relay...")
		connection, err = net.Dial("tcp", net.JoinHostPort(*relayHost, chat.DefaultPort))
	} else {
		d, err := proxy.SOCKS5("tcp", *socksAddress,
			&proxy.Auth{User: *name, Password: "x"}, // auth so clients go through different TOR circuits
			proxy.Direct,
		)
		if err != nil {
			return fmt.Errorf("failed to create SOCKS dial: %v", err)
		}
		log.Println("sat up SOCKS")

		log.Printf("connecting to relay at %s...", *relayHost)
		connection, err = d.Dial("tcp", net.JoinHostPort(*relayHost, chat.DefaultPort))
	}

	if err != nil {
		return fmt.Errorf("failed to connect to relay: %v", err)
	}
	defer func() { _ = connection.Close() }()
	log.Println("connected to relay")

	// create client
	client := client{
		conn:             connection,
		name:             *name,
		payloadSendChan:  make(chan []byte, payloadChanSize),
		password:         password,
		cpaceContext:     chat.MakeCpaceContext(),
		handshakeOutChan: make(chan chat.Frame, chat.RoomCap-1),
		keyReadyChan:     make(chan cipher.AEAD, 1),
	}

	// before continuing anything else, do onboarding
	err = client.handleOnboarding()
	if err != nil {
		return fmt.Errorf("onboarding failed: %v", err)
	}

	// launch all the goroutines
	errChan := make(chan error, 3)
	go func() {
		errChan <- client.receive()
	}()
	go func() {
		errChan <- client.send()
	}()
	go func() {
		errChan <- client.handleInput()
	}()
	return <-errChan
}

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
			// no aead means that the client has not yet joined a room, ignore data frames
			if c.aead == nil {
				continue
			}

			// open data to access plaintext
			plaintext, err := chat.OpenData(c.aead, frame)
			if errors.Is(err, chat.ErrOpen) {
				continue // ErrOpen drops silently if the frame is tampered with
			}
			if err != nil {
				log.Println("failed to open frame: ", err)
				continue
			}

			// ignore dummies
			if plaintext.Flag == chat.FlagDummy {
				continue
			}

			fmt.Println(string(plaintext.Payload))
		case chat.KindHandshake:
			handshake, err := chat.ParseHandshake(frame)
			if err != nil {
				log.Println("failed to parse handshake: ", err)
				continue
			}

			if c.kRoom != nil {
				// client is a member, check if subtype is correct, then exchange, wrap, reply
				if handshake.Subtype != chat.SubtypeMsgA {
					// normal traffic, ignore
					continue
				}

				msgB, memberISK, err := cpace.Exchange(c.password, c.cpaceContext, handshake.MsgA)
				if err != nil {
					log.Println("failed to exchange: ", err)
					continue
				}
				wrap, err := chat.SealWrap(memberISK, c.kRoom)
				if err != nil {
					log.Println("failed to seal wrap: ", err)
					continue
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
					continue
				}

				if !bytes.Equal(handshake.Sid, c.sid) {
					// sid does not match, this is normal when two joiners overlap, just ignore
					continue
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

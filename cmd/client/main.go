package main

import (
	"bufio"
	"crypto/cipher"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/xLTJ/unobservable_chat/chat"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/net/proxy"
)

type client struct {
	conn            net.Conn
	name            string
	payloadSendChan chan []byte
	aead            cipher.AEAD
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
	var connection net.Conn
	var err error

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

	// create AEAD
	aead, err := chacha20poly1305.NewX([]byte(chat.TestKey))
	if err != nil {
		return fmt.Errorf("failed to create AEAD: %v", err)
	}

	// create client
	client := client{
		conn:            connection,
		name:            *name,
		payloadSendChan: make(chan []byte, payloadChanSize),
		aead:            aead,
	}

	// new and improved awesome error handling
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

func (c *client) receive() error {
	for {
		cell, err := chat.ReadCell(c.conn)
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

		// open data to access plaintext
		plaintext, err := chat.OpenData(c.aead, frame)
		if errors.Is(err, chat.ErrOpen) {
			continue // ErrOpen drops silently if the frame is tampered with
		}
		if err != nil {
			log.Println("Failed to open frame: ", err)
			continue
		}

		// ignore dummies
		if plaintext.Flag == chat.FlagDummy {
			continue
		}

		fmt.Println(string(plaintext.Payload))
	}
}

func (c *client) send() error {
	ticker := time.NewTicker(chat.Tick)
	defer ticker.Stop()

	for range ticker.C {
		var plaintext chat.Plaintext

		// if a payload is queued, create a message from it, otherwise create a dummy message
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
		frame, err := chat.SealData(c.aead, plaintext)
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
		if len(payload) > chat.PayloadMax {
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

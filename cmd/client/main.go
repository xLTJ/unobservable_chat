package main

import (
	"crypto/cipher"
	"flag"
	"fmt"
	"log"
	"net"
	"os"

	"filippo.io/cpace"
	"github.com/xLTJ/unobservable_chat/chat"
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

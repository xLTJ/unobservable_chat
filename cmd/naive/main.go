package main

import (
	"crypto/cipher"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"time"
	"unicode/utf8"

	"github.com/xLTJ/unobservable_chat/chat"
	"golang.org/x/net/proxy"
)

type client struct {
	conn            net.Conn
	name            string
	payloadSendChan chan []byte

	aead     cipher.AEAD
	kRoom    []byte
	roomName string

	keyReadyChan chan cipher.AEAD // channel to pass the key to the send goroutine, avoiding a race condition

	messagesInProgress map[[4]byte]*inProgress // messages in progress, keyed by sender id
}

// inProgress is used to keep track of fragmented messages that are being received
type inProgress struct {
	msgNum            uint16
	nextFragmentIndex byte
	body              []byte
}

const payloadChanSize = 100

// flags
var name = flag.String("name", "Anonymous", "name to display")
var room = flag.String("room", "", "name of room to join")
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

	// then the room name
	roomName, err := chat.NormaliseRoomName(*room)
	if err != nil {
		return fmt.Errorf("failed to normalise room name: %v", err)
	}

	// check if the display name is valid
	if len(*name) > chat.DisplayNameMaxLen || len(*name) == 0 {
		return fmt.Errorf("invalid display name size: %q", *name)
	}
	if !utf8.ValidString(*name) {
		return fmt.Errorf("invalid display name: %q", *name)
	}

	startTime := time.Now()
	kRoom := chat.NaiveKey(password, roomName)
	log.Printf("key generation took %v\n", time.Since(startTime))

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
		conn:               connection,
		name:               *name,
		payloadSendChan:    make(chan []byte, payloadChanSize),
		roomName:           roomName,
		keyReadyChan:       make(chan cipher.AEAD, 1),
		messagesInProgress: make(map[[4]byte]*inProgress),
		kRoom:              kRoom,
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

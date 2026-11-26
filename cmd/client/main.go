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
	roomName string
	password string

	sid              []byte
	cpaceState       *cpace.State
	cpaceContext     *cpace.ContextInfo
	handshakeOutChan chan chat.Frame  // channel for outgoing handshake messages
	keyReadyChan     chan cipher.AEAD // channel to pass the key to the send goroutine, avoiding a race condition

	messagesInProgress map[[4]byte]*inProgress // messages in progress, keyed by sender id

	timingLog *log.Logger // timing logger
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
var timingLogPath = flag.String("timing", "", "path to timing log. logs are off when empty")

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

	// set up timing log
	var timingLog *log.Logger
	if *timingLogPath != "" {
		// open timing log. write-only, create if it doesn't exist, truncate (overwrite) if it does
		timingLogFile, err := os.OpenFile(*timingLogPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			return fmt.Errorf("failed to open timing log: %v", err)
		}
		defer func() { _ = timingLogFile.Close() }()
		timingLog = log.New(timingLogFile, "", 0)
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
		conn:               connection,
		name:               *name,
		payloadSendChan:    make(chan []byte, payloadChanSize),
		password:           password,
		roomName:           roomName,
		cpaceContext:       chat.MakeCpaceContext(roomName),
		handshakeOutChan:   make(chan chat.Frame, chat.RoomCap-1),
		keyReadyChan:       make(chan cipher.AEAD, 1),
		messagesInProgress: make(map[[4]byte]*inProgress),
		timingLog:          timingLog,
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

// logCell writes a timing-log line. does nothing when -timing flag is off.
func (c *client) logCell(timeStamp time.Time, direction, event string) {
	if c.timingLog == nil {
		return
	}
	c.timingLog.Printf("%d %s %s", timeStamp.UnixMicro(), direction, event)
}

// dataEvent names a data cell for the timing log, from its plaintext.
func dataEvent(plaintext chat.Plaintext) string {
	switch {
	case plaintext.Flag == chat.FlagDummy:
		return "dummy"
	case plaintext.Last:
		return "msg"
	default:
		return "frag"
	}
}

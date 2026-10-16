package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/xLTJ/unobservable_chat/chat"
	"golang.org/x/net/proxy"
)

type client struct {
	conn net.Conn
	name string
}

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
	log.Println("connecting to relay...")
	if *socksAddress == "" {
		connection, err = net.Dial("tcp", net.JoinHostPort(*relayHost, chat.DefaultPort))
	} else {
		d, err := proxy.SOCKS5("tcp", *socksAddress,
			nil, // no auth rn
			proxy.Direct,
		)
		if err != nil {
			return fmt.Errorf("failed to create SOCKS dial: %v", err)
		}
		log.Println("sat up SOCKS")

		connection, err = d.Dial("tcp", net.JoinHostPort(*relayHost, chat.DefaultPort))
	}

	if err != nil {
		return fmt.Errorf("failed to connect to relay: %v", err)
	}
	defer func() { _ = connection.Close() }()
	fmt.Println("connected to relay")

	// create client
	client := client{
		conn: connection,
		name: *name,
	}

	// new and improved awesome error handling
	errChan := make(chan error, 2)
	go func() {
		errChan <- client.receive()
	}()
	go func() {
		errChan <- client.send()
	}()
	return <-errChan
}

func (c *client) receive() error {
	for {
		cell, err := chat.ReadCell(c.conn)
		if err != nil {
			return fmt.Errorf("failed to read from server: %v", err)
		}

		// decode frame, then print it
		frame, err := chat.Decode(cell)
		if err != nil {
			// drop invalid frames
			log.Println("Failed to decode frame: ", err)
			continue
		}

		var name string
		var seq, sentUs int
		fmt.Sscanf(string(frame.Body[:]), "%s %d %d", &name, &seq, &sentUs)
		fmt.Printf("Name %s, Seq %d, SentUs %d\n", name, seq, sentUs)
	}
}

func (c *client) send() error {
	ticker := time.NewTicker(chat.Tick)
	defer ticker.Stop()

	seq := 1

	for {
		select {
		case <-ticker.C:
			frame := chat.Frame{
				Kind: chat.KindData,
				Body: [chat.BodySize]byte{},
			}

			message := fmt.Sprintf("%s %d %d", c.name, seq, time.Now().UnixMicro())
			copy(frame.Body[:], message)
			cell, err := frame.Encode()
			if err != nil {
				return fmt.Errorf("failed to encode frame: %v", err)
			}

			_, err = c.conn.Write(cell[:])
			if err != nil {
				return fmt.Errorf("failed to write to server: %v", err)
			}
			seq++
		}
	}
}

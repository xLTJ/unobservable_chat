package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/xLTJ/unobservable_chat/chat"
)

type client struct {
	conn net.Conn
	name string
}

var name = flag.String("name", "Anonymous", "name to display")

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
	connection, err := net.Dial("tcp", chat.DefaultPort)
	if err != nil {
		return fmt.Errorf("failed to connect to server: %v", err)
	}
	defer func() { _ = connection.Close() }()

	fmt.Println("connected to relay")

	// create client
	client := client{
		conn: connection,
		name: *name,
	}

	// launch read loop
	go client.receive()

	// launch write loop. currently just creating automated debug messages
	go client.send()

	return nil
}

func (c *client) receive() {
	buffer := chat.Cell{}
	for {
		_, err := c.conn.Read(buffer[:])
		if err != nil {
			log.Fatalf("Failed to read from server: %v", err)
		}

		// decode frame, then print it
		frame, err := chat.Decode(buffer)
		if err != nil {
			log.Fatalf("Failed to decode frame: %v", err)
		}

		var name string
		var seq, sentUs int
		fmt.Sscanf(string(frame.Body[:]), "%s %d %d", &name, &seq, &sentUs)
		fmt.Printf("Name %s, Seq %d, SentUs %d\n", name, seq, sentUs)
	}
}

func (c *client) send() error {
	ticker := time.NewTicker(chat.Tick)
	done := make(chan bool)

	seq := 1

	for {
		select {
		case <-done:
			return nil
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

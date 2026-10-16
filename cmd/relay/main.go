package main

import (
	"context"
	"errors"
	"log"
	"net"
	"os/signal"
	"syscall"

	"github.com/xLTJ/unobservable_chat/chat"
)

type user struct {
	conn          net.Conn
	incomingCells chan userCell
}

type userCell struct {
	user *user
	cell chat.Cell
}

type room struct {
	users      map[*user]bool
	addUser    chan *user
	removeUser chan *user
	cells      chan userCell
}

// startRoom runs the room's event loop. launch as a goroutine
func (r *room) startRoom() {
	for {
		select {
		case user := <-r.addUser:
			r.users[user] = true
			log.Println("user joined room")

		case user := <-r.removeUser:
			// if the user is not in the room (like if they were already removed), ignore
			if _, ok := r.users[user]; !ok {
				continue
			}

			_ = user.conn.Close()
			close(user.incomingCells)
			delete(r.users, user)
			log.Println("removed user from room")

		case cell := <-r.cells:
			for user := range r.users {
				// skip sending to the user who sent the cell
				if user == cell.user {
					continue
				}

				select {
				case user.incomingCells <- cell:
				default:
					// if the user's incomingCells channel is full, drop the cell and log
					log.Println("user's incomingCells channel is full, dropping cell")
				}
			}
		}
	}
}

func main() {
	// do whatever here idk

	// run relay, log any exit errors
	err := run()
	if err != nil {
		log.Fatal(err)
	}
}

func run() error {
	listener, err := net.Listen("tcp", chat.DefaultPort)
	if err != nil {
		return err
	}
	defer func() { _ = listener.Close() }()

	room := room{
		users:      make(map[*user]bool),
		addUser:    make(chan *user),
		removeUser: make(chan *user),
		cells:      make(chan userCell),
	}
	go room.startRoom()

	// launch accept loop
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				// if the listener is closed, return
				if errors.Is(err, net.ErrClosed) {
					return
				}

				// other accept errors are non-fatal, just log them
				log.Println("Failed to accept connection: ", err)
				continue
			}

			user := user{
				conn:          conn,
				incomingCells: make(chan userCell, 8),
			}
			go handleUser(&user, &room)
		}
	}()

	// wait for SIGINT or SIGTERM (basically, ctrl+c)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()

	log.Println("Shutting down...")
	_ = listener.Close()

	log.Println("Shutdown complete")
	return nil
}

func handleUser(user *user, room *room) {
	room.addUser <- user

	go receiveCells(user, room)

	sendCells(user, room)
}

// receiveCells reads cells from the user's connection and sends them to the room's cells channel
func receiveCells(user *user, room *room) {
	for {
		cell, err := chat.ReadCell(user.conn)
		if err != nil {
			log.Println("Failed to read from connection: ", err)
			room.removeUser <- user
			break
		}

		room.cells <- userCell{user: user, cell: cell}
	}
}

// sendCells reads from the user's incomingCells channel and sends them to the user's connection
func sendCells(user *user, room *room) {
	for incomingCell := range user.incomingCells {
		_, err := user.conn.Write(incomingCell.cell[:])
		if err != nil {
			log.Println("Failed to write to connection: ", err)
			room.removeUser <- user
			break
		}
	}
}

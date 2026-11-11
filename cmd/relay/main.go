package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net"
	"os/signal"
	"syscall"

	"github.com/xLTJ/unobservable_chat/chat"
)

const outboxSize = 8

// user is a connected user in the chat system.
// it holds the user's connection and a channel for the user's outbox (cells that goes out to the user)
type user struct {
	conn          net.Conn
	outbox        chan userCell
	roomId        roomId
	arrivalNumber int
}

type room struct {
	users             map[*user]bool
	nextArrivalNumber int
}

type roomId struct {
	roomName string
	roomMode chat.Mode
}

// userCell holds the user who sent the cell and the cell itself
type userCell struct {
	user *user
	cell chat.Cell
}

type relay struct {
	addUser    chan *user
	removeUser chan *user
	cells      chan userCell
}

// flags
var verboseLogging = flag.Bool("v", false, "enable verbose logging")

// runRooms runs the relay's event loop. launch as a goroutine
func (r *relay) runRooms() {
	rooms := make(map[roomId]*room)

	for {
		select {
		case u := <-r.addUser:
			// look up the room, create it if it doesnt exist
			rm, ok := rooms[u.roomId]
			if !ok {
				newRoom := &room{users: make(map[*user]bool)}
				rooms[u.roomId] = newRoom
				rm = newRoom
			}

			// send the user a control frame with the number of users in the room
			userCount := len(rm.users)
			controlFrame := chat.MakeControlFrame(userCount)
			controlCell, err := controlFrame.Encode()
			if err != nil {
				log.Println("Error: failed to encode control frame: ", err)
				close(u.outbox)
				continue
			}
			u.outbox <- userCell{cell: controlCell}

			// if the room is full, kill their outbox and dont add the user
			if userCount == chat.RoomCap {
				close(u.outbox)
				continue
			}

			// add the user to the room
			rm.users[u] = true
			u.arrivalNumber = rm.nextArrivalNumber
			rm.nextArrivalNumber++
			log.Printf("added user to room %s\n", u.roomId.roomName)

		case u := <-r.removeUser:
			rm, ok := rooms[u.roomId]

			// if the room doesnt exist, or the user is not in the room (like if they were already removed), ignore
			if !ok {
				continue
			}
			if _, ok := rm.users[u]; !ok {
				continue
			}

			close(u.outbox)
			delete(rm.users, u)
			log.Printf("removed user from room %s\n", u.roomId.roomName)

			// if the room is now empty, remove it too
			if len(rm.users) == 0 {
				delete(rooms, u.roomId)
				log.Printf("removed room %s\n", u.roomId.roomName)
			}

		case c := <-r.cells:
			rm, ok := rooms[c.user.roomId]

			// if the room doesnt exist, or the user is not in the room, ignore
			if !ok {
				continue
			}
			if _, ok := rm.users[c.user]; !ok {
				continue
			}

			// handshake cells with msgA subtype get special treatment; only gets sent to the oldest user in the room
			cellType := chat.Kind(c.cell[0])
			if cellType == chat.KindHandshake {
				cellSubType := chat.Subtype(c.cell[1])

				if cellSubType == chat.SubtypeMsgA {
					// find the oldest member in the room
					var oldestMember *user
					for u := range rm.users {
						if u == c.user {
							continue
						}

						if oldestMember == nil || u.arrivalNumber < oldestMember.arrivalNumber {
							oldestMember = u
						}
					}

					// no other members in the room, drop the cell
					if oldestMember == nil {
						log.Println("no other members, dropping cell")
						continue
					}

					select {
					case oldestMember.outbox <- c:
					default:
						log.Println("oldest member's outbox channel is full, dropping cell")
					}

					continue
				}
			}

			// send the cell to all users in the room
			for u := range rm.users {
				// skip sending to the user who sent the cell
				if u == c.user {
					continue
				}

				select {
				case u.outbox <- c:
				default:
					// if the user's outbox channel is full, drop the cell and log
					log.Println("user's outbox channel is full, dropping cell")
				}
			}
		}
	}
}

func main() {
	// do whatever here idk
	flag.Parse()

	// run relay, log any exit errors
	err := run()
	if err != nil {
		log.Fatal(err)
	}
}

func run() error {
	listener, err := net.Listen("tcp", "127.0.0.1:"+chat.DefaultPort)
	if err != nil {
		return err
	}
	defer func() { _ = listener.Close() }()

	r := relay{
		addUser:    make(chan *user),
		removeUser: make(chan *user),
		cells:      make(chan userCell),
	}
	go r.runRooms()

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
				log.Println("Error: failed to accept connection: ", err)
				continue
			}

			u := user{
				conn:   conn,
				outbox: make(chan userCell, outboxSize),
			}
			go handleUser(&u, &r)
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

func handleUser(u *user, r *relay) {
	// close the connection when the function returns
	defer func() { _ = u.conn.Close() }()

	// read hello cell from user
	helloCell, err := chat.ReadCell(u.conn)
	if err != nil {
		log.Println("Error: Failed to read from connection: ", err)
		return
	}
	if *verboseLogging {
		log.Printf("Received hello cell: %s\n", helloCell)
	}

	helloFrame, err := chat.Decode(helloCell)
	if err != nil {
		log.Println("Error: failed to decode hello cell: ", err)
		return
	}
	if helloFrame.Kind != chat.KindHello {
		log.Println("Error: received invalid hello cell kind: ", helloFrame.Kind)
		return
	}

	mode, name, err := chat.ParseHello(helloFrame)
	if err != nil {
		log.Println("Error: failed to parse hello cell: ", err)
		return
	}
	u.roomId = roomId{roomName: name, roomMode: mode}

	r.addUser <- u
	go receiveCells(u, r)
	sendCells(u, r)
}

// receiveCells reads cells from the user's connection and sends them to the relay's cells channel
func receiveCells(u *user, r *relay) {
	for {
		cell, err := chat.ReadCell(u.conn)
		if err != nil {
			log.Println("Error: Failed to read from connection: ", err)
			r.removeUser <- u
			break
		}

		if *verboseLogging {
			log.Printf("Received cell: %s\n", cell)
		}

		// relay only forwards data and handshake frames to other users
		cellKind := chat.Kind(cell[0])
		if cellKind != chat.KindData && cellKind != chat.KindHandshake {
			log.Println("Error: received invalid cell kind: ", cellKind)
			continue
		}

		r.cells <- userCell{user: u, cell: cell}
	}
}

// sendCells reads from the user's outbox channel and sends them to the user's connection
func sendCells(u *user, r *relay) {
	for cell := range u.outbox {
		_, err := u.conn.Write(cell.cell[:])
		if err != nil {
			log.Println("Error: failed to write to connection: ", err)
			r.removeUser <- u
			break
		}
	}
}

package main

import (
	"bufio"
	"crypto/cipher"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/xLTJ/unobservable_chat/chat"
	"golang.org/x/crypto/chacha20poly1305"
)

var room = flag.String("room", "", "name of the room")
var wordlist = flag.String("wordlist", "", "path to wordlist")
var cellPath = flag.String("cell", "", "path to captured cell")
var fullCapture = flag.Bool("full", false, "whether to use full capture")
var capturePath = flag.String("capture", "", "path to capture file")

// attack tool for evaluation, so code is rushed and probably not the best
func main() {
	flag.Parse()

	if *fullCapture {
		analyzeCapture()
	} else {
		// read cell and decode it
		cellContent, err := os.ReadFile(*cellPath)
		if err != nil {
			panic("error reading cell file: " + err.Error())
		}
		capturedFrame, err := chat.Decode(chat.Cell(cellContent))
		if err != nil {
			panic("error decoding cell: " + err.Error())
		}

		findPassword(capturedFrame)
	}
}

func analyzeCapture() {
	captureFile, err := os.Open(*capturePath)
	if err != nil {
		panic("error opening capture file: " + err.Error())
	}
	defer func() { _ = captureFile.Close() }()

	// first find a data frame to use as target
	var targetFrame chat.Frame
	for {
		cell, err := chat.ReadCell(captureFile)
		if errors.Is(err, io.EOF) {
			break // end of file
		}
		if err != nil {
			// something went wrong
			panic("error reading capture file: " + err.Error())
		}
		frame, err := chat.Decode(cell)
		if err != nil || frame.Kind != chat.KindData {
			continue
		}
		targetFrame = frame
		fmt.Println("Found target frame")
		break
	}

	// then find password
	password, foundAEAD, err := findPassword(targetFrame)
	if err != nil {
		panic(err)
	}
	if password == "" {
		panic("no match found")
	}

	// now decrypt everything
	_, err = captureFile.Seek(0, io.SeekStart) // reset file position
	if err != nil {
		panic("error resetting capture file: " + err.Error())
	}

	messageNum := 0
	dummyNum := 0

	fmt.Println("----------- Decrypted messages -----------")
	for {
		cell, err := chat.ReadCell(captureFile)
		if errors.Is(err, io.EOF) {
			break // end of file
		}
		if err != nil {
			// something went wrong
			panic("error reading capture file: " + err.Error())
		}
		frame, err := chat.Decode(cell)
		if err != nil || frame.Kind != chat.KindData {
			continue
		}
		plaintext, err := chat.OpenData(foundAEAD, frame)
		if err != nil {
			panic(err)
		}
		if plaintext.Flag == chat.FlagDummy {
			dummyNum++
			continue
		}
		name, text, err := chat.ParseBody(plaintext.Payload)
		if err != nil {
			panic(err)
		}

		fmt.Printf("%s: %s\n", name, text)
		messageNum++
	}

	fmt.Println("----------- Stats -----------")
	fmt.Printf("Messages: %d\n", messageNum)
	fmt.Printf("Dummy messages: %d\n", dummyNum)
	fmt.Printf("Total cells: %d\n", messageNum+dummyNum)
}

func findPassword(frame chat.Frame) (string, cipher.AEAD, error) {
	wordlistFile, err := os.Open(*wordlist)
	if err != nil {
		panic("error opening wordlist: " + err.Error())
	}
	defer func() { _ = wordlistFile.Close() }()

	if frame.Kind != chat.KindData {
		panic("frame is not a data cell")
	}

	roomName, err := chat.NormaliseRoomName(*room)
	if err != nil {
		panic("error normalising room name: " + err.Error())
	}

	i := 0
	startTime := time.Now()
	scanner := bufio.NewScanner(wordlistFile)
	for scanner.Scan() {
		password := scanner.Text()
		normalizedPassword, err := chat.NormalisePassword(password)
		if err != nil {
			continue // guess is invalid, just skip
		}

		i++
		fmt.Printf("Trying password: %s\n", normalizedPassword)

		key := chat.NaiveKey(normalizedPassword, roomName)
		aead, _ := chacha20poly1305.NewX(key)
		_, err = chat.OpenData(aead, frame)
		if err == nil {
			fmt.Println("----------- Found! -----------")
			fmt.Println("Password: ", password)
			fmt.Println("Time: ", time.Since(startTime))
			fmt.Println("Iterations: ", i)
			return password, aead, nil
		}
	}

	err = scanner.Err()
	if err != nil {
		return "", nil, err
	}
	fmt.Println("No match found")
	return "", nil, nil
}

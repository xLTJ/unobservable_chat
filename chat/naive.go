package chat

import (
	"crypto/sha256"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

// argon2id constants, from RFC 9106 §4's second option:
// t=3 iterations, p=4 lanes, m=2^(16) (64 MiB of RAM)
const (
	NaiveArgonIterations  = 3
	NaiveArgonMemory      = 64 * 1024 // in KiB
	NaiveArgonParallelism = 4
)

const (
	naiveSaltLabel = "unobservable-chat v1 naive"
	NaiveSaltSize  = 16
)

// NaiveSalt returns a salt for the given room name
func NaiveSalt(roomName string) []byte {
	saltInput := naiveSaltLabel + roomName
	saltChecksum := sha256.Sum256([]byte(saltInput))
	return saltChecksum[:NaiveSaltSize]
}

// NaiveKey returns the key for the given password and room name. both inputs must be normalized.
func NaiveKey(password, roomName string) []byte {
	salt := NaiveSalt(roomName)
	return argon2.IDKey(
		[]byte(password),
		salt,
		NaiveArgonIterations,
		NaiveArgonMemory,
		NaiveArgonParallelism,
		chacha20poly1305.KeySize,
	)
}

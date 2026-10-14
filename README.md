# Unobservable Chat

A multi-party, storage-free chat that hides not only what is said but whether anyone is talking.

Written in Go as a first-semester project.

## Status

Work in progress, let's call it v0.1 or something. A relay and a test client exchange fixed-size cells on localhost.

## Contents

- `chat/params.go` - shared constants
- `chat/cell.go` - the fixed-size cell, has definitions and methods for encoding and decoding
- `cmd/relay` - the relay. Forwards every cell it receives to every other connected client.
- `cmd/client` - a test client. Sends one test cell per tick and prints the cells it receives.

## Build and run

```
go build -o bin/ ./cmd/...
bin/relay
bin/client -name a    # in a second terminal
bin/client -name b    # in a third
```

The relay listens on `127.0.0.1:9735`.

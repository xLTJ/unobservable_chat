# Unobservable Chat

A multi-party, storage-free chat that hides not only what is said but whether anyone is talking.

Written in Go as a first-semester project.

## Status

Work in progress, let's call it v0.1 or something. A relay and a test client exchange fixed-size cells on localhost.

At the moment, every instruction here assumes everything runs locally in the same machine.

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

## Setting up Tor

It's easiest to have everything in the same parent directory, let's call it `~/tor` or something, it doesn't matter

Create these two files:

**server.torrc**

```
DataDirectory <directory, rec: ~/tor/server-data>
SocksPort 0
HiddenServiceDir <directory, rec: ~/tor/hs>
HiddenServicePort 9735 127.0.0.1:9735
Log notice stdout
```

**client.torrc**

```
DataDirectory <directory, rec: ~/tor/client-data>
SocksPort 9052
TestSocks 1
SafeSocks 1
Log notice stdout
```

Then run both

```shell
tor -f service.torrc
tor -f client.torrc
```

And that's it. The hostname can be found inside `<HiddenServiceDir>/hostname`

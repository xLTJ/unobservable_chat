package main

import (
	"flag"
	"fmt"
	"log"
	"math/rand/v2"
	"os"
	"strings"
	"time"

	"github.com/xLTJ/unobservable_chat/chat"
)

// flags
var phaseLogPath = flag.String("log", "", "REQUIRED: path to write logs to")
var activeMessageRate = flag.Float64("rate", 0.2, "rate of messages per second")
var phaseMinDuration = flag.Duration("phase-min", 20*time.Second, "minimum duration of a phase")
var phaseMaxDuration = flag.Duration("phase-max", 90*time.Second, "maximum duration of a phase")
var startPhaseDuration = flag.Duration("start", 15*time.Second, "settle time before the first phase starts")
var runDuration = flag.Duration("duration", 5*time.Minute, "duration of the run, counted from after settling")
var lineLength = flag.Int("length", 50, "length of each line in bytes")
var seed = flag.Uint64("seed", 1, "PRNG seed")

func main() {
	flag.Parse()

	// run client, log any exit errors
	err := run()
	if err != nil {
		log.Fatal(err)
	}
}

func run() error {
	// check flags
	err := checkFlags()
	if err != nil {
		return err
	}

	// set up logging
	phaseLogFile, err := os.OpenFile(*phaseLogPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("failed to open phase log: %v", err)
	}
	defer func() { _ = phaseLogFile.Close() }()
	phaseLog := log.New(phaseLogFile, "", 0)

	// closure to log events
	logEvent := func(event string) {
		phaseLog.Printf("%d %s", time.Now().UnixMicro(), event)
	}

	// ready the loop
	rng := rand.New(rand.NewPCG(*seed, 0))
	lineText := strings.Repeat("a", *lineLength) // line to write. content doesnt matter, its encrypted anyway
	time.Sleep(*startPhaseDuration)              // settle phase, allows joiner to enter room before the first phase starts

	phaseStart := time.Now()
	runEnd := phaseStart.Add(*runDuration)
	active := rng.IntN(2) == 0 // 50% chance of first phase being active

	// and begin the run
	for phaseStart.Before(runEnd) {
		// set up the next phase
		phaseLength := *phaseMinDuration + time.Duration(rng.Int64N(int64(*phaseMaxDuration-*phaseMinDuration+1)))
		phaseEnd := phaseStart.Add(phaseLength)
		if phaseEnd.After(runEnd) {
			phaseEnd = runEnd
		}

		if active {
			logEvent("phase active")
			sendLineAt := phaseStart
			for {
				// lines are sent according to a poisson process with mean `1/activeMessageRate`
				gap := time.Duration(rng.ExpFloat64() / *activeMessageRate * float64(time.Second))
				sendLineAt = sendLineAt.Add(gap)

				// if the next line would be sent after the phase ends, just wait until the phase ends and break
				if sendLineAt.After(phaseEnd) {
					time.Sleep(time.Until(phaseEnd))
					break
				}

				time.Sleep(time.Until(sendLineAt))
				fmt.Println(lineText)
				logEvent("line")
			}
		} else {
			logEvent("phase idle")
			time.Sleep(time.Until(phaseEnd))
		}

		// ready the next phase
		phaseStart = phaseEnd
		active = !active
	}

	logEvent("end")
	return nil
}

// checkFlags checks the flags and returns an error if any are invalid
func checkFlags() error {
	if *phaseLogPath == "" {
		return fmt.Errorf("log path is required")
	}

	if *activeMessageRate <= 0 {
		return fmt.Errorf("active message rate must be above zero")
	}

	if *phaseMinDuration <= 0 || *phaseMinDuration > *phaseMaxDuration {
		return fmt.Errorf("phase min duration must be above zero and less than phase max duration")
	}

	if *lineLength <= 0 || *lineLength > chat.MessageMaxLen {
		return fmt.Errorf("line length must be above zero and less than message max length")
	}

	if *startPhaseDuration < 0 || *runDuration <= 0 {
		return fmt.Errorf("start phase duration must not be negative, and run duration must be above zero")
	}

	return nil
}

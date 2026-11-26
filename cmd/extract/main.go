package main

import (
	"bufio"
	"encoding/csv"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	captureFileName  = "capture.pcapng"
	phasesFileName   = "phases.log"
	talkerFileName   = "talker.timing"
	listenerFileName = "listener.timing"
	runInfoFileName  = "run.info"
)

type segment struct {
	captureTime     int64 // unix microseconds
	sourcePort      string
	destinationPort string
	payload         int // tcp.len
}

func main() {
	flag.Parse()

	// run extractor, log any exit errors
	if err := run(flag.Args()); err != nil {
		log.Fatal(err)
	}
}
func run(runDirectories []string) error {
	if len(runDirectories) == 0 {
		return fmt.Errorf("usage: extract [-window 10s] <run-dir>...")
	}

	csvWriter := csv.NewWriter(os.Stdout)
	// header once, here
	for _, runDirectory := range runDirectories {
		if err := extractRun(runDirectory, csvWriter); err != nil {
			return fmt.Errorf("%s: %v", runDirectory, err)
		}
	}
	csvWriter.Flush()
	return csvWriter.Error()
}

func extractRun(runDirectory string, csvWriter *csv.Writer) error {
	runName := filepath.Base(runDirectory)

	// parse all the files
	segments, err := parseCaptureFile(filepath.Join(runDirectory, captureFileName))
	if err != nil {
		return fmt.Errorf("failed to read segments: %v", err)
	}
	runStart, runEnd, err := parsePhasesLog(filepath.Join(runDirectory, phasesFileName))
	if err != nil {
		return fmt.Errorf("failed to read phases log: %v", err)
	}
	talkerMessageTimes, talkerHelloTime, err := parseTimingsLog(filepath.Join(runDirectory, talkerFileName), "up")
	if err != nil {
		return fmt.Errorf("failed to read talker timings log: %v", err)
	}
	listenerMessageTimes, listenerHelloTime, err := parseTimingsLog(filepath.Join(runDirectory, listenerFileName), "down")
	if err != nil {
		return fmt.Errorf("failed to read listener timings log: %v", err)
	}
	seed, build, err := parseRunInfo(filepath.Join(runDirectory, runInfoFileName))

	return nil
}

// parseCaptureFile reads the segments from the capture file and returns them as a slice
func parseCaptureFile(filePath string) ([]segment, error) {
	// run tshark to read the segments from the capture file
	tsharkCommand := exec.Command("tshark", "-r", filePath, "-Y", "tcp.len > 0",
		"-T", "fields", "-E", "separator=,",
		"-e", "frame.time_epoch", "-e", "tcp.srcport", "-e", "tcp.dstport", "-e", "tcp.len")
	tsharkOutput, err := tsharkCommand.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdout pipe: %v", err)
	}
	tsharkCommand.Stderr = os.Stderr // log errors to stderr
	if err := tsharkCommand.Start(); err != nil {
		return nil, fmt.Errorf("failed to start tshark: %v", err)
	}

	// then read the output to extract segments
	lineScanner := bufio.NewScanner(tsharkOutput)
	var segments []segment
	for lineScanner.Scan() {
		// each line is a segment with 4 fields (comma separated). if it's not 4 fields, something went horribly wrong
		// fields in order: capture time, source port, destination port, payload length
		fields := strings.Split(lineScanner.Text(), ",")
		if len(fields) != 4 {
			return nil, fmt.Errorf("invalid tshark output: %q", lineScanner.Text())
		}

		captureTime, err := parseEpochMicros(fields[0])
		if err != nil {
			return nil, fmt.Errorf("failed to parse capture time: %v", err)
		}
		payload, err := strconv.Atoi(fields[3])
		if err != nil {
			return nil, fmt.Errorf("failed to parse payload length: %v", err)
		}

		segments = append(segments, segment{
			captureTime:     captureTime,
			sourcePort:      fields[1],
			destinationPort: fields[2],
			payload:         payload,
		})
	}

	if err := lineScanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read tshark output: %v", err)
	}
	if err := tsharkCommand.Wait(); err != nil {
		return nil, fmt.Errorf("failed to wait for tshark: %v", err)
	}
	return segments, nil
}

// parsePhasesLog reads the phases log and returns the start and end times of the run
// everything else in the log is irrelevant here
func parsePhasesLog(filePath string) (runStart, runEnd int64, err error) {
	phasesLog, err := os.Open(filePath)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to open phases log: %v", err)
	}
	defer func() { _ = phasesLog.Close() }()

	scanner := bufio.NewScanner(phasesLog)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			return 0, 0, fmt.Errorf("invalid phases log: %q", scanner.Text())
		}

		timestamp, err := strconv.ParseInt(fields[0], 10, 64)
		if err != nil {
			return 0, 0, fmt.Errorf("failed to parse timestamp: %v", err)
		}
		eventType := fields[1]

		// find the start and end of the grid
		if runStart == 0 && eventType == "phase" {
			runStart = timestamp
			continue
		}
		if eventType == "end" {
			if runStart == 0 {
				return 0, 0, fmt.Errorf("run start not found in phases log")
			}

			runEnd = timestamp
			if runStart >= runEnd {
				return 0, 0, fmt.Errorf("run start is somehow after or equal to run end")
			}
			return runStart, runEnd, nil
		}
	}

	if err := scanner.Err(); err != nil {
		return 0, 0, fmt.Errorf("failed to read phases log: %v", err)
	}
	return 0, 0, fmt.Errorf("run start and end not found in phases log")
}

// parseTimingsLog reads the timings log and returns the message (msg + frag) times for the given direction
// up for talker, down for listener
// also returns the hello time for the client (always up)
// all other events are irrelevant here
func parseTimingsLog(filePath, direction string) (messageTimes []int64, helloTime int64, err error) {
	timingsLog, err := os.Open(filePath)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to open timings log: %v", err)
	}
	defer func() { _ = timingsLog.Close() }()

	scanner := bufio.NewScanner(timingsLog)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) != 3 {
			return nil, 0, fmt.Errorf("invalid timings log: %q", scanner.Text())
		}

		eventDirection := fields[1]
		event := fields[2]

		// for hello we want the up direction no matter what
		if eventDirection == "up" && event == "hello" {
			if helloTime != 0 {
				return nil, 0, fmt.Errorf("two hello events found in timings log in the same direction")
			}
			helloTime, err = strconv.ParseInt(fields[0], 10, 64)
			if err != nil {
				return nil, 0, fmt.Errorf("failed to parse hello time: %v", err)
			}
			continue
		}

		// skip the rest if its not the right direction
		if eventDirection != direction {
			continue
		}

		// add message and fragment times to the list
		if event == "msg" || event == "frag" {
			timestamp, err := strconv.ParseInt(fields[0], 10, 64)
			if err != nil {
				return nil, 0, fmt.Errorf("failed to parse timestamp: %v", err)
			}
			messageTimes = append(messageTimes, timestamp)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, 0, fmt.Errorf("failed to read timings log: %v", err)
	}
	return messageTimes, helloTime, nil
}

// parseRunInfo reads the run info file and returns the seed and build number
func parseRunInfo(filePath string) (seed uint64, build string, err error) {
	runInfo, err := os.Open(filePath)
	if err != nil {
		return 0, "", fmt.Errorf("failed to open run info: %v", err)
	}
	defer func() { _ = runInfo.Close() }()

	scanner := bufio.NewScanner(runInfo)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "seed: ") {
			seed, err = strconv.ParseUint(strings.TrimPrefix(line, "seed: "), 10, 64)
			if err != nil {
				return 0, "", fmt.Errorf("failed to parse seed: %v", err)
			}
			continue
		}

		if strings.HasPrefix(line, "build: ") {
			build = strings.TrimPrefix(line, "build: ")
			continue
		}
	}

	if err := scanner.Err(); err != nil {
		return 0, "", fmt.Errorf("failed to read run info: %v", err)
	}
	if seed == 0 || build == "" {
		return 0, "", fmt.Errorf("seed and/or build not found in run info")
	}
	return seed, build, nil
}

// parseEpochMicros turns tshark's frame.time_epoch, e.g. "1795652736.682746658",
// into Unix microseconds, e.g. 1795652736682746
func parseEpochMicros(epochText string) (int64, error) {
	secondsText, fractionText, found := strings.Cut(epochText, ".")
	if !found || len(fractionText) != 9 {
		return 0, fmt.Errorf("invalid frame.time_epoch format: %q", epochText)
	}
	nanoseconds, err := strconv.ParseInt(secondsText+fractionText, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("failed to parse frame.time_epoch: %v", err)
	}
	return nanoseconds / 1000, nil
}

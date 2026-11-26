#!/usr/bin/env bash

set -u

if [ $# -lt 3 ]; then
	echo "usage: $0 <bin-dir> <seed> <out-dir> [generator flags...]" >&2
	exit 2
fi
binDir=$1
seed=$2
outDir=$3
shift 3

port=9735
room=exp2
export UC_PASSWORD=${UC_PASSWORD:-exp2-local}

for program in relay client generator; do
	if [ ! -x "$binDir/$program" ]; then
		echo "missing $binDir/$program; build first" >&2
		exit 2
	fi
done
if [ -n "$(ss -Hltn "sport = :$port")" ]; then
	echo "port $port is in use; stop the running relay first" >&2
	exit 2
fi
if [ -e "$outDir" ]; then
	echo "$outDir exists; give a new output directory" >&2
	exit 2
fi
mkdir -p "$outDir"
outDir=$(cd "$outDir" && pwd)
binDir=$(cd "$binDir" && pwd)

fifoDir=$(mktemp -d)
pids=""

# stop whatever is still running when the script exits, for any reason
cleanup() {
	for pid in $pids; do
		kill "$pid" 2>/dev/null
	done
	rm -rf "$fifoDir"
}
trap cleanup EXIT

fail() {
	echo "run failed: $*" | tee -a "$outDir/run.info" >&2
	exit 1
}

# wait up to $1 seconds for the command in the remaining arguments to succeed
waitFor() {
	local seconds=$1
	shift
	for _ in $(seq $((seconds * 10))); do
		"$@" && return 0
		sleep 0.1
	done
	return 1
}

{
	echo "started: $(date -Is)"
	echo "bin-dir: $binDir"
	echo "seed: $seed"
	echo "generator flags: $*"
	echo "client build info:"
	go version -m "$binDir/client" 2>/dev/null | grep -E 'build\s+(-tags|-race|vcs\.revision|vcs\.modified)' || echo "  (go not on PATH)"
} > "$outDir/run.info"

# 1. capture
dumpcap -q -i lo -f "tcp port $port" -w "$outDir/capture.pcapng" 2> "$outDir/dumpcap.err" &
capturePid=$!
pids="$pids $capturePid"
waitFor 5 test -s "$outDir/capture.pcapng" || fail "dumpcap did not start (see dumpcap.err)"
sleep 1

# 2. relay
"$binDir/relay" 2> "$outDir/relay.err" &
relayPid=$!
pids="$pids $relayPid"
relayListening() { [ -n "$(ss -Hltn "sport = :$port")" ]; }
waitFor 5 relayListening || fail "relay did not start (see relay.err)"

# 3. listener: founds the room and never types
"$binDir/client" -name listener -room "$room" -timing "$outDir/listener.timing" \
	< /dev/null > "$outDir/listener.out" 2> "$outDir/listener.err" &
listenerPid=$!
pids="$pids $listenerPid"
waitFor 10 grep -q "room successfully created" "$outDir/listener.err" || fail "listener did not found the room (see listener.err)"

# 4. talker, fed by the generator through a named pipe
mkfifo "$fifoDir/talker.in"
"$binDir/client" -name talker -room "$room" -timing "$outDir/talker.timing" \
	< "$fifoDir/talker.in" > "$outDir/talker.out" 2> "$outDir/talker.err" &
talkerPid=$!
pids="$pids $talkerPid"
"$binDir/generator" -seed "$seed" -log "$outDir/phases.log" "$@" \
	> "$fifoDir/talker.in" 2> "$outDir/generator.err" &
generatorPid=$!
pids="$pids $generatorPid"

# 5. wait for the generator; a talker that dies first fails the run
while kill -0 "$generatorPid" 2>/dev/null; do
	if ! kill -0 "$talkerPid" 2>/dev/null; then
		grep -q "no reply from the room" "$outDir/talker.err" && fail "talker got no reply from the room; restart the run"
		fail "talker exited early (see talker.err)"
	fi
	sleep 1
done
wait "$generatorPid"
generatorStatus=$?
[ "$generatorStatus" -eq 0 ] || fail "generator exited with $generatorStatus (see generator.err)"

# a few ticks for the last line's cells to arrive and be logged
sleep 3

kill "$talkerPid" "$listenerPid" 2>/dev/null
sleep 0.5
kill "$relayPid" 2>/dev/null
sleep 1
kill "$capturePid" 2>/dev/null
wait 2>/dev/null
pids=""

# one for one: generator lines = talker's up msg = listener's down msg = listener's printed lines
lines=$(grep -c ' line$' "$outDir/phases.log")
talkerUp=$(grep -c ' up msg$' "$outDir/talker.timing")
listenerDown=$(grep -c ' down msg$' "$outDir/listener.timing")
printed=$(wc -l < "$outDir/listener.out")
{
	echo "stopped: $(date -Is)"
	echo "generator lines: $lines, talker up msg: $talkerUp, listener down msg: $listenerDown, listener printed: $printed"
} | tee -a "$outDir/run.info"

if [ "$lines" -ne "$talkerUp" ] || [ "$lines" -ne "$listenerDown" ] || [ "$lines" -ne "$printed" ]; then
	fail "counts differ"
fi
echo "run ok: $outDir"

#!/usr/bin/env bash
# Runs functions/test/*.test.js against a standalone Firestore emulator.
#
# Not run via `firebase emulators:exec`: that wrapper hangs indefinitely on
# this test file specifically (confirmed by isolating the same test file
# against a manually-started emulator, where it passes in ~5s). The
# difference from firestore-tests/ (which runs fine under emulators:exec) is
# that sendCameraNotification logs a full Error via firebase-functions'
# structured JSON logger on the failure-path tests; emulators:exec appears to
# stall reading child stdout once a line that long/JSON-escaped appears.
# Starting the emulator directly and running node --test against it
# sidesteps that entirely.
set -euo pipefail

cd "$(dirname "$0")/.."

rm -f firestore-debug.log

firebase emulators:start --only firestore --project demo-edgeguard-rules-test &
EMULATOR_PID=$!

cleanup() {
  kill "$EMULATOR_PID" 2>/dev/null || true
  wait "$EMULATOR_PID" 2>/dev/null || true
}
trap cleanup EXIT

for _ in $(seq 1 60); do
  if curl -s -o /dev/null "http://127.0.0.1:8080"; then
    break
  fi
  sleep 1
done

# --test-concurrency=1 forces Node's test runner to run these test files one
# at a time (each functions/test/*.test.js file is executed as its own
# child process by default, and Node runs multiple such files concurrently
# unless told otherwise). Without this, entitlements.test.js,
# notifications.test.js, and turn-credentials.test.js all start at once,
# right as the readiness loop above first observes port 8080 accepting
# connections -- three fresh Admin SDK Firestore clients then race to open
# their first connection to the emulator in the same narrow instant, and
# the emulator (whose HTTP listener can already answer the plain curl probe
# above while it is still finishing internal startup) refuses one or more
# of them with "14 UNAVAILABLE: connect ECONNREFUSED 127.0.0.1:8080" before
# the underlying gRPC client's own retry/backoff eventually succeeds tens of
# seconds later. Serializing file execution means only one file's process is
# ever newly connecting to the emulator at a time, and every file after the
# first starts well after the emulator has been handling real traffic for a
# while, so this exact startup race can no longer occur.
FIRESTORE_EMULATOR_HOST=127.0.0.1:8080 GCLOUD_PROJECT=demo-edgeguard-rules-test node --test --test-concurrency=1 functions/test/*.test.js

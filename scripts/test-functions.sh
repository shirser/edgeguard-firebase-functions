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

FIRESTORE_EMULATOR_HOST=127.0.0.1:8080 GCLOUD_PROJECT=demo-edgeguard-rules-test node --test functions/test/*.test.js

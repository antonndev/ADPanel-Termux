#!/usr/bin/env bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY="$SCRIPT_DIR/adpanel"

if [ ! -f "$BINARY" ]; then
  echo "Binary not found. Run ./initialize.sh first to build."
  exit 1
fi

echo "Starting ADPanel..."
cd "$SCRIPT_DIR" && nohup "$BINARY" serve > /dev/null 2>&1 &
echo "Panel started (PID: $!). Run 'kill $!' to stop."

#!/bin/bash
# Warp Security Audit - Teardown Script
# Cleans up all test artifacts

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=== Warp Security Audit Teardown ==="

# Remove test artifacts
if [ -d "$SCRIPT_DIR/artifacts" ]; then
    echo "Removing artifacts directory..."
    rm -rf "$SCRIPT_DIR/artifacts"
fi

if [ -d "$SCRIPT_DIR/results" ]; then
    echo "Removing results directory..."
    rm -rf "$SCRIPT_DIR/results"
fi

# Remove Python venv if created
if [ -d "$SCRIPT_DIR/.venv" ]; then
    echo "Removing Python virtual environment..."
    rm -rf "$SCRIPT_DIR/.venv"
fi

# Remove any test socket files we may have created
rm -f /tmp/warp-audit-test-*.sock 2>/dev/null || true

echo "=== Teardown Complete ==="

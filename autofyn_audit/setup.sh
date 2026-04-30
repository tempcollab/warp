#!/bin/bash
# Warp Security Audit - Setup Script
# Commit: 404bfbeb8f4a2e07ca9063b45993590609416c98
# Date: 2026-04-29

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
AUDIT_DIR="$SCRIPT_DIR"

echo "=== Warp Security Audit Setup ==="
echo "Commit: 404bfbeb8f4a2e07ca9063b45993590609416c98"
echo "Audit Directory: $AUDIT_DIR"

# Verify we're at the correct commit
CURRENT_COMMIT=$(git -C "$REPO_ROOT" rev-parse HEAD)
EXPECTED_COMMIT="404bfbeb8f4a2e07ca9063b45993590609416c98"

if [ "$CURRENT_COMMIT" != "$EXPECTED_COMMIT" ]; then
    echo "WARNING: Current commit ($CURRENT_COMMIT) differs from audited commit ($EXPECTED_COMMIT)"
fi

# Create directories for test artifacts
mkdir -p "$AUDIT_DIR/artifacts"
mkdir -p "$AUDIT_DIR/results"

# Extract static encryption key from source for verification
echo "[1/4] Extracting hardcoded secrets from source..."
grep -n "releases.warp.dev/channel_versions.json" "$REPO_ROOT/crates/warpui_extras/src/secure_storage/linux.rs" > "$AUDIT_DIR/artifacts/static_key_evidence.txt" 2>/dev/null || true

# Extract Firebase API key from source
grep -rn "AIzaSy" "$REPO_ROOT/crates/warp_core/src/channel/config.rs" >> "$AUDIT_DIR/artifacts/hardcoded_secrets.txt" 2>/dev/null || true

echo "[2/4] Verifying IPC vulnerability code paths..."
# Verify IPC unbounded allocation vulnerability exists
grep -n "vec!\[0; payload_len\]" "$REPO_ROOT/crates/ipc/src/protocol.rs" > "$AUDIT_DIR/artifacts/ipc_vuln_evidence.txt" 2>/dev/null || true

echo "[3/4] Checking for dangerous CLI flags in AI harness..."
grep -rn "dangerously-skip-permissions" "$REPO_ROOT/app/src/ai/" > "$AUDIT_DIR/artifacts/dangerous_flags_evidence.txt" 2>/dev/null || true
grep -rn "\-\-yolo" "$REPO_ROOT/app/src/ai/" >> "$AUDIT_DIR/artifacts/dangerous_flags_evidence.txt" 2>/dev/null || true

echo "[4/4] Creating Python virtual environment for exploit scripts..."
if command -v python3 &> /dev/null; then
    python3 -m venv "$AUDIT_DIR/.venv" 2>/dev/null || echo "venv creation skipped (may already exist or not needed)"
    if [ -d "$AUDIT_DIR/.venv" ]; then
        "$AUDIT_DIR/.venv/bin/pip" install --quiet cryptography requests 2>/dev/null || echo "pip install skipped (install manually: pip install cryptography requests)"
    fi
fi

echo ""
echo "=== Setup Complete ==="
echo "Artifacts extracted to: $AUDIT_DIR/artifacts/"
echo "Run ./run_all_exploits.sh to execute vulnerability verification"

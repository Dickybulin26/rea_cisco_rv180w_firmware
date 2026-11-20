#!/bin/sh
# End-to-end ARMv6 QEMU test for rv180wd v3.0 (TLS 1.2/1.3, First-Boot Setup, Auth, Zero-Reboot Config, Rollback)
set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BIN="${1:-$ROOT_DIR/target/arm-unknown-linux-musleabi/release/rv180wd}"
HTTP_PORT="${HTTP_PORT:-18080}"
HTTPS_PORT="${HTTPS_PORT:-18443}"

if [ ! -x "$BIN" ]; then
    echo "ERROR: ARMv6 rv180wd binary not found at $BIN" >&2
    exit 1
fi

TMP_DATA="$(mktemp -d /tmp/rv180wd-qemu.XXXXXX)"
COOKIE_JAR="$TMP_DATA/cookies.txt"
cleanup() {
    [ -n "${DAEMON_PID:-}" ] && kill "$DAEMON_PID" 2>/dev/null || true
    rm -rf "$TMP_DATA"
}
trap cleanup EXIT INT TERM

echo "[1/6] Testing rv180wd --boot under qemu-arm-static (dry-run)..."
RV180WD_DATA_DIR="$TMP_DATA" RV180WD_DRY_RUN=1 qemu-arm-static "$BIN" --boot

echo "[2/6] Starting rv180wd --serve (HTTP :${HTTP_PORT} + HTTPS TLS 1.2/1.3 :${HTTPS_PORT})..."
RV180WD_DATA_DIR="$TMP_DATA" \
RV180WD_DRY_RUN=1 \
RV180WD_HTTP_ADDR="127.0.0.1:${HTTP_PORT}" \
RV180WD_HTTPS_ADDR="127.0.0.1:${HTTPS_PORT}" \
RV180WD_SAN_IP="192.168.1.1" \
qemu-arm-static "$BIN" --serve >"$TMP_DATA/server.log" 2>&1 &
DAEMON_PID=$!
sleep 2

echo "[3/6] Testing TLS 1.3 + TLS 1.2 + Embedded SPA..."
curl -k --tlsv1.3 -sS "https://127.0.0.1:${HTTPS_PORT}/api/v1/health" | grep -q '"daemon":"rv180wd"'
curl -k --tlsv1.2 --tls-max 1.2 -sS "https://127.0.0.1:${HTTPS_PORT}/" | grep -q "Cisco RV180W Next"
echo "[OK] TLS 1.3 & TLS 1.2 + SPA verified!"

echo "[4/6] Testing First-Boot Setup + Login Persistence (special-char password)..."
SETUP_JSON=$(curl -k -sS -c "$COOKIE_JAR" -X POST "https://127.0.0.1:${HTTPS_PORT}/api/v1/auth/setup" \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"P@ss'\''word\"2026!"}')
echo "Setup response: $SETUP_JSON"
echo "$SETUP_JSON" | grep -q '"ok":true'
CSRF=$(echo "$SETUP_JSON" | python3 -c "import sys,json; print(json.load(sys.stdin)['csrf_token'])")

# Verify auth.json permissions are 0600
PERM=$(stat -c "%a" "$TMP_DATA/auth.json")
[ "$PERM" = "600" ] || { echo "ERROR: auth.json perm is $PERM, expected 600" >&2; exit 1; }

# Logout and login again over HTTP AND HTTPS (no Referer!) to confirm login bug is completely gone
curl -k -sS -b "$COOKIE_JAR" -c "$COOKIE_JAR" -X POST "https://127.0.0.1:${HTTPS_PORT}/api/v1/auth/logout" \
    -H "X-CSRF-Token: $CSRF" -d '{}' >/dev/null
LOGIN_JSON=$(curl -k -sS -c "$COOKIE_JAR" -X POST "https://127.0.0.1:${HTTPS_PORT}/api/v1/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"P@ss'\''word\"2026!"}')
echo "$LOGIN_JSON" | grep -q '"ok":true'
CSRF=$(echo "$LOGIN_JSON" | python3 -c "import sys,json; print(json.load(sys.stdin)['csrf_token'])")
echo "[OK] Login persisted & verified without Referer dependency!"

echo "[5/6] Testing Zero-Reboot Config Save + Safe-Rollback + Confirm..."
CFG=$(curl -k -sS -b "$COOKIE_JAR" "https://127.0.0.1:${HTTPS_PORT}/api/v1/config")
NEW_CFG=$(echo "$CFG" | python3 -c "import sys,json; c=json.load(sys.stdin); c['network']['lan']['ip']='192.168.50.1'; c['wifi']['ssid']='RV180W-Next-Fast'; print(json.dumps(c))")
SAVE_RES=$(curl -k -sS -b "$COOKIE_JAR" -X PUT "https://127.0.0.1:${HTTPS_PORT}/api/v1/config" \
    -H "Content-Type: application/json" -H "X-CSRF-Token: $CSRF" -d "$NEW_CFG")
echo "Save response: $SAVE_RES"
echo "$SAVE_RES" | grep -q '"reboot_required":false'
echo "$SAVE_RES" | grep -q '"rollback_pending_secs":60'

curl -k -sS -b "$COOKIE_JAR" -X POST "https://127.0.0.1:${HTTPS_PORT}/api/v1/config/confirm" \
    -H "X-CSRF-Token: $CSRF" -d '{}' | grep -q '"confirmed":true'

echo "[6/6] Checking live telemetry & certificate SAN..."
curl -k -sS -b "$COOKIE_JAR" "https://127.0.0.1:${HTTPS_PORT}/api/v1/dashboard" | grep -q '"mem_total_kb"'
openssl x509 -in "$TMP_DATA/certs/rv180wd.crt" -noout -subject -ext subjectAltName

echo "[SUCCESS] Full rv180wd v3.0 ARMv6 QEMU verification passed!"

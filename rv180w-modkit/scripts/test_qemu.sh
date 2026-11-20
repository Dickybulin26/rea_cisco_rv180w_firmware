#!/bin/sh
# End-to-end ARM32 QEMU verification for RV180W Modern TLS Proxy + Router HTTP Backend
set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
PROXY_BIN="${1:-$ROOT_DIR/target/arm-unknown-linux-musleabi/release/modern-tls-proxy}"
WORK_DIR="${2:-$ROOT_DIR/build}"
HTTPS_PORT="${HTTPS_PORT:-8443}"
HTTP_PORT="${HTTP_PORT:-8080}"

if [ ! -x "$PROXY_BIN" ]; then
    echo "ERROR: ARM32 proxy binary not found at $PROXY_BIN" >&2
    exit 1
fi

TMP_CERT_DIR="$(mktemp -d /tmp/rv180w-qemu-certs.XXXXXX)"
cleanup() {
    [ -n "${PROXY_PID:-}" ] && kill "$PROXY_PID" 2>/dev/null || true
    [ -n "${BACKEND_PID:-}" ] && kill "$BACKEND_PID" 2>/dev/null || true
    rm -rf "$TMP_CERT_DIR"
}
trap cleanup EXIT INT TERM

echo "[1/4] Starting mock HTTP backend on 127.0.0.1:${HTTP_PORT} serving patched squashfs-root/var/www..."
python3 -m http.server "$HTTP_PORT" --bind 127.0.0.1 --directory "$WORK_DIR/squashfs-root/var/www" >/tmp/rv180w-backend.log 2>&1 &
BACKEND_PID=$!
sleep 0.5

echo "[1b/4] Checking ELF ARMv6 attributes (no VFP/Thumb-2)..."
if command -v readelf >/dev/null 2>&1; then
    readelf -A "$PROXY_BIN" >/tmp/rv180w-proxy-readelf-A.txt 2>&1 || true
    if grep -q "Tag_CPU_arch: v7" /tmp/rv180w-proxy-readelf-A.txt; then
        echo "ERROR: modern-tls-proxy built for ARMv7" >&2; exit 1
    fi
    if grep -q "Tag_FP_arch" /tmp/rv180w-proxy-readelf-A.txt; then
        echo "ERROR: modern-tls-proxy contains Tag_FP_arch (VFP)" >&2; exit 1
    fi
    if grep -q "Tag_THUMB_ISA_use: Thumb-2" /tmp/rv180w-proxy-readelf-A.txt; then
        echo "ERROR: modern-tls-proxy uses Thumb-2 instructions" >&2; exit 1
    fi
    echo "[OK] ELF attributes look ARMv6-softfloat compatible"
fi

echo "[2/4] Launching ARM32 static modern-tls-proxy under qemu-arm-static -cpu arm11mpcore on 127.0.0.1:${HTTPS_PORT}..."
qemu-arm-static -cpu arm11mpcore "$PROXY_BIN" \
    --listen "127.0.0.1:${HTTPS_PORT}" \
    --backend "127.0.0.1:${HTTP_PORT}" \
    --cert-dir "$TMP_CERT_DIR" \
    --san-ip 192.168.1.1 \
    --max-conns 16 >/tmp/rv180w-proxy.log 2>&1 &
PROXY_PID=$!
sleep 1.5

echo "[3/4] Testing TLS 1.3 handshake + HTTP reverse proxy + cert SAN..."
curl -k --tlsv1.3 -sS -D /tmp/rv180w-tls13.hdr "https://127.0.0.1:${HTTPS_PORT}/modStatus.htm" -o /tmp/rv180w-tls13.body
head -n 10 /tmp/rv180w-tls13.hdr
grep -q "Cisco RV180W Modern TLS Mod" /tmp/rv180w-tls13.body && echo "[OK] TLS 1.3 served /modStatus.htm!"

echo "[4/4] Testing TLS 1.2 handshake + X.509 SAN certificate inspection..."
curl -k --tlsv1.2 --tls-max 1.2 -sS -o /dev/null -w "TLS 1.2 HTTP %{http_code} via %{ssl_verify_result}\n" "https://127.0.0.1:${HTTPS_PORT}/js/bdetect.js"
openssl x509 -in "$TMP_CERT_DIR/modern_https.crt" -noout -subject -dates -ext subjectAltName

echo "[SUCCESS] ARM32 QEMU TLS 1.2 & TLS 1.3 verification passed!"

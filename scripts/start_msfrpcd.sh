#!/usr/bin/env bash
# =============================================================================
# AutoVAPT — Start Metasploit RPC Daemon (msfrpcd)
# Run this before using AutoVAPT's exploit validation phase.
# Usage: ./scripts/start_msfrpcd.sh
# =============================================================================

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

info()    { echo -e "${CYAN}[*]${RESET} $*"; }
success() { echo -e "${GREEN}[✓]${RESET} $*"; }
warn()    { echo -e "${YELLOW}[!]${RESET} $*"; }
error()   { echo -e "${RED}[✗]${RESET} $*"; exit 1; }

# ── Config ────────────────────────────────────────────────────────────────────
MSF_HOST="127.0.0.1"
MSF_PORT="55553"
MSF_USER="msf"
MSF_PASS="msf"
MSF_PID_FILE="/tmp/msfrpcd.pid"
MSF_LOG_FILE="/tmp/msfrpcd.log"

echo -e "${CYAN}${BOLD}"
echo "  ┌─────────────────────────────────────────┐"
echo "  │   Metasploit RPC Daemon Launcher         │"
echo "  └─────────────────────────────────────────┘"
echo -e "${RESET}"

# ── Check Metasploit installed ────────────────────────────────────────────────
if ! command -v msfrpcd &>/dev/null; then
    error "msfrpcd not found. Install Metasploit: sudo apt install metasploit-framework"
fi

# ── Check if already running ──────────────────────────────────────────────────
if [[ -f "$MSF_PID_FILE" ]]; then
    PID=$(cat "$MSF_PID_FILE")
    if kill -0 "$PID" 2>/dev/null; then
        warn "msfrpcd already running (PID $PID) on ${MSF_HOST}:${MSF_PORT}"
        echo ""
        echo -e "  To stop it: ${CYAN}kill $PID${RESET}"
        exit 0
    else
        rm -f "$MSF_PID_FILE"
    fi
fi

# ── Start msfrpcd ─────────────────────────────────────────────────────────────
info "Starting Metasploit RPC daemon..."
info "  Host     : $MSF_HOST"
info "  Port     : $MSF_PORT"
info "  Username : $MSF_USER"
info "  Password : $MSF_PASS"
info "  Log file : $MSF_LOG_FILE"
echo ""

msfrpcd \
    -P "$MSF_PASS" \
    -U "$MSF_USER" \
    -a "$MSF_HOST" \
    -p "$MSF_PORT" \
    -S \
    -f \
    > "$MSF_LOG_FILE" 2>&1 &

RPCD_PID=$!
echo "$RPCD_PID" > "$MSF_PID_FILE"

# ── Wait for startup ──────────────────────────────────────────────────────────
info "Waiting for msfrpcd to start (up to 20 seconds)..."
for i in {1..20}; do
    if nc -z "$MSF_HOST" "$MSF_PORT" 2>/dev/null; then
        success "msfrpcd is up and listening! (PID $RPCD_PID)"
        echo ""
        echo -e "  ${BOLD}AutoVAPT can now use Metasploit exploit validation.${RESET}"
        echo -e "  Run: ${CYAN}python3 main.py --target <IP>${RESET}"
        echo ""
        echo -e "  To stop the daemon later: ${CYAN}kill $RPCD_PID${RESET}"
        exit 0
    fi
    sleep 1
    echo -n "."
done

echo ""
error "msfrpcd did not start within 20 seconds. Check logs: $MSF_LOG_FILE"

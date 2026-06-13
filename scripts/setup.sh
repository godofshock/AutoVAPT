#!/usr/bin/env bash
# =============================================================================
# AutoVAPT — One-Command Setup Script
# Tested on: Kali Linux 2023.x / 2024.x, Debian 12, Ubuntu 22.04+
# Usage: chmod +x scripts/setup.sh && sudo ./scripts/setup.sh
# =============================================================================

set -euo pipefail

# ── Colours ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

info()    { echo -e "${CYAN}[*]${RESET} $*"; }
success() { echo -e "${GREEN}[✓]${RESET} $*"; }
warn()    { echo -e "${YELLOW}[!]${RESET} $*"; }
error()   { echo -e "${RED}[✗]${RESET} $*"; exit 1; }

# ── Banner ────────────────────────────────────────────────────────────────────
echo -e "${RED}"
cat << 'EOF'
    _         _       __   ___   ___ _____
   / \  _   _| |_ ___\ \ / / \ / _ \_   _|
  / _ \| | | | __/ _ \\ V /|  _  || |
 / ___ \ |_| | || (_) || | | | | || |
/_/   \_\__,_|\__\___/ |_| |_| |_||_|

EOF
echo -e "${RESET}${BOLD}  AutoVAPT Setup — Automated VAPT Framework${RESET}"
echo -e "  ──────────────────────────────────────────"
echo ""

# ── Root check ────────────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    error "This script must be run as root: sudo ./scripts/setup.sh"
fi

# ── OS detection ──────────────────────────────────────────────────────────────
if [[ ! -f /etc/os-release ]]; then
    error "Cannot detect OS. This script supports Kali/Debian/Ubuntu only."
fi
source /etc/os-release
info "Detected OS: ${PRETTY_NAME}"

# ── Step 1: System package update ────────────────────────────────────────────
info "Updating system package list..."
apt-get update -qq
success "Package list updated."

# ── Step 2: System dependencies ──────────────────────────────────────────────
info "Installing system dependencies..."
PACKAGES=(
    nmap
    python3
    python3-pip
    python3-dev
    build-essential
    libssl-dev
    libffi-dev
    git
    curl
    wget
)

for pkg in "${PACKAGES[@]}"; do
    if dpkg -s "$pkg" &>/dev/null; then
        info "  $pkg already installed — skipping."
    else
        apt-get install -y -qq "$pkg"
        success "  Installed: $pkg"
    fi
done

# ── Step 3: Metasploit Framework ──────────────────────────────────────────────
if command -v msfconsole &>/dev/null; then
    success "Metasploit Framework already installed."
else
    warn "Metasploit Framework not found."
    read -rp "  Install Metasploit now? (recommended) [y/N]: " install_msf
    if [[ "$install_msf" =~ ^[Yy]$ ]]; then
        info "Installing Metasploit Framework (this may take a few minutes)..."
        apt-get install -y -qq metasploit-framework
        success "Metasploit Framework installed."
    else
        warn "Skipping Metasploit. Exploit validation will use manual fallback mode."
    fi
fi

# ── Step 4: Python dependencies ───────────────────────────────────────────────
info "Installing Python dependencies from requirements.txt..."
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

if [[ ! -f "$PROJECT_ROOT/requirements.txt" ]]; then
    error "requirements.txt not found at $PROJECT_ROOT"
fi

pip install -r "$PROJECT_ROOT/requirements.txt" \
    --break-system-packages \
    --quiet \
    --no-warn-script-location
success "Python dependencies installed."

# ── Step 5: Create output directories ─────────────────────────────────────────
info "Creating output directories..."
mkdir -p "$PROJECT_ROOT/reports"
mkdir -p "$PROJECT_ROOT/logs"
success "Directories ready: reports/ logs/"

# ── Step 6: Config file ───────────────────────────────────────────────────────
if [[ ! -f "$PROJECT_ROOT/config.yaml" ]]; then
    cp "$PROJECT_ROOT/config.yaml.example" "$PROJECT_ROOT/config.yaml" 2>/dev/null || true
    success "config.yaml created from template."
else
    info "config.yaml already exists — skipping."
fi

# ── Step 7: Permissions ───────────────────────────────────────────────────────
chmod +x "$PROJECT_ROOT/main.py"
chmod +x "$PROJECT_ROOT/scripts/"*.sh 2>/dev/null || true
success "Permissions set."

# ── Step 8: Verify nmap ───────────────────────────────────────────────────────
info "Verifying nmap..."
NMAP_VER=$(nmap --version | head -1)
success "nmap found: $NMAP_VER"

# ── Step 9: Python smoke test ─────────────────────────────────────────────────
info "Running import smoke test..."
python3 -c "
import sys
sys.path.insert(0, '$PROJECT_ROOT')
from autovapt.utils.config import Config
from autovapt.utils.nvd_client import NVDClient
from autovapt.modules.risk_scorer import RiskScorer
print('  All core imports OK')
"
success "Smoke test passed."

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════════════╗${RESET}"
echo -e "${GREEN}${BOLD}║           AutoVAPT setup complete!                  ║${RESET}"
echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════════════════╝${RESET}"
echo ""
echo -e "  ${BOLD}Quick start:${RESET}"
echo -e "  ${CYAN}python3 main.py --target 192.168.56.101${RESET}"
echo ""
echo -e "  ${BOLD}Start Metasploit RPC daemon:${RESET}"
echo -e "  ${CYAN}./scripts/start_msfrpcd.sh${RESET}"
echo ""
echo -e "  ${BOLD}Optional — set your NVD API key for higher rate limits:${RESET}"
echo -e "  ${CYAN}export NVD_API_KEY=your_key_here${RESET}"
echo -e "  Get a free key: ${CYAN}https://nvd.nist.gov/developers/request-an-api-key${RESET}"
echo ""

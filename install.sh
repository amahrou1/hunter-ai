#!/usr/bin/env bash
# hunter-ai installer.
# Safe to run again at any time: it only installs what is missing.
# Usage: bash ~/hunter-ai/install.sh            (first install)
#        bash ~/hunter-ai/install.sh --update   (called by: hunt update)
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODE="${1:-install}"
APT_ENV=(env DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a)

say()  { printf '\n==> %s\n' "$*"; }
fail() { printf '\nERROR: %s\nSend everything above this line to Claude.\n' "$*" >&2; exit 1; }

if [ "$(id -u)" -eq 0 ]; then
  fail "Do not run this as root. Log in as user hunter and run it again."
fi

if [ -r /etc/os-release ]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  case "${ID:-}" in
    ubuntu|debian) ;;
    *) say "Warning: hunter-ai is tested on Ubuntu. Found: ${PRETTY_NAME:-unknown}" ;;
  esac
fi

# --- 1. System packages -------------------------------------------------
APT_PACKAGES=(git curl jq tmux sqlite3 unzip ca-certificates python3 python3-venv python3-pip)
missing=()
for pkg in "${APT_PACKAGES[@]}"; do
  dpkg -s "$pkg" >/dev/null 2>&1 || missing+=("$pkg")
done
if [ "${#missing[@]}" -gt 0 ]; then
  say "Installing system packages: ${missing[*]}"
  echo "You may be asked once for the password of user $USER."
  sudo "${APT_ENV[@]}" apt-get update -y
  sudo "${APT_ENV[@]}" apt-get install -y "${missing[@]}"
fi

# --- 2. Python 3.10 or newer ---------------------------------------------
pick_python() {
  local candidate
  for candidate in python3.13 python3.12 python3.11 python3.10 python3; do
    if command -v "$candidate" >/dev/null 2>&1 &&
       "$candidate" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' 2>/dev/null; then
      echo "$candidate"
      return 0
    fi
  done
  return 1
}

PY="$(pick_python || true)"
if [ -z "$PY" ]; then
  say "The system Python is too old. Installing Python 3.11."
  sudo "${APT_ENV[@]}" apt-get install -y software-properties-common
  sudo add-apt-repository -y ppa:deadsnakes/ppa
  sudo "${APT_ENV[@]}" apt-get update -y
  sudo "${APT_ENV[@]}" apt-get install -y python3.11 python3.11-venv
  PY="python3.11"
fi

VENV="$REPO_DIR/.venv"
if [ ! -x "$VENV/bin/python" ]; then
  say "Creating the private Python environment"
  if ! "$PY" -m venv "$VENV" >/dev/null 2>&1; then
    PYVER="$("$PY" -c 'import sys; print(f"{sys.version_info[0]}.{sys.version_info[1]}")')"
    rm -rf "$VENV"
    sudo "${APT_ENV[@]}" apt-get install -y "python${PYVER}-venv"
    "$PY" -m venv "$VENV" || fail "Could not create the Python environment."
  fi
fi
"$VENV/bin/python" -m pip install --quiet --upgrade pip
"$VENV/bin/python" -m pip install --quiet -r "$REPO_DIR/requirements.txt"

# --- 3. Claude Code (the agent runtime) ---------------------------------
export PATH="$HOME/.local/bin:$PATH"
if ! command -v claude >/dev/null 2>&1; then
  say "Installing Claude Code"
  if ! curl -fsSL https://claude.ai/install.sh | bash; then
    fail "Claude Code could not be downloaded from claude.ai. Check the internet connection and run the installer again."
  fi
fi
command -v claude >/dev/null 2>&1 || fail "Claude Code could not be installed."

# --- 4. The hunt command ------------------------------------------------
mkdir -p "$HOME/.local/bin"
chmod +x "$REPO_DIR/bin/hunt"
ln -sf "$REPO_DIR/bin/hunt" "$HOME/.local/bin/hunt"
if ! grep -qs 'hunter-ai: PATH' "$HOME/.bashrc"; then
  # shellcheck disable=SC2016  # $HOME and $PATH must stay literal in .bashrc
  printf '\n# hunter-ai: PATH\nexport PATH="$HOME/.local/bin:$PATH"\n' >> "$HOME/.bashrc"
fi
mkdir -p "$HOME/.config/hunter-ai" "$HOME/targets"
chmod 700 "$HOME/.config/hunter-ai"

# --- 5. Self-check ------------------------------------------------------
"$REPO_DIR/bin/hunt" version >/dev/null || fail "The hunt command does not start."

say "hunter-ai $("$REPO_DIR/bin/hunt" version | awk '{print $2}') is installed."
if [ "$MODE" != "--update" ]; then
  cat <<'NEXT'

Next steps (type them one by one):
  exec bash -l
  hunt setup
  hunt doctor
NEXT
fi

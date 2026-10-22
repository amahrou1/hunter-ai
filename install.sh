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
# Ubuntu 22.04+ already has a new enough Python. On older systems (for
# example Ubuntu 20.04) uv downloads a private Python 3.12 for hunter-ai
# only; the system Python is not changed and no sudo is needed.
export PATH="$HOME/.local/bin:$PATH"
VENV="$REPO_DIR/.venv"

py_ok() {
  "$1" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' >/dev/null 2>&1
}

pick_python() {
  local candidate
  for candidate in python3.13 python3.12 python3.11 python3.10 python3; do
    if command -v "$candidate" >/dev/null 2>&1 && py_ok "$candidate"; then
      echo "$candidate"
      return 0
    fi
  done
  return 1
}

ensure_uv() {
  if command -v uv >/dev/null 2>&1; then
    return 0
  fi
  say "Installing uv (it provides a modern Python for hunter-ai only)"
  if ! curl -LsSf https://astral.sh/uv/install.sh | env UV_NO_MODIFY_PATH=1 sh; then
    fail "uv could not be downloaded from astral.sh. Check the internet connection and run the installer again."
  fi
  command -v uv >/dev/null 2>&1 || fail "uv was installed but cannot be found in ~/.local/bin."
}

if [ -x "$VENV/bin/python" ] && ! py_ok "$VENV/bin/python"; then
  rm -rf "$VENV"
fi

if [ ! -x "$VENV/bin/python" ]; then
  PY="$(pick_python || true)"
  if [ -n "$PY" ] && [ "${HUNTER_FORCE_UV:-0}" != "1" ]; then
    say "Creating the private Python environment ($("$PY" --version 2>&1))"
    if ! "$PY" -m venv "$VENV" >/dev/null 2>&1; then
      PYVER="$("$PY" -c 'import sys; print(f"{sys.version_info[0]}.{sys.version_info[1]}")')"
      rm -rf "$VENV"
      sudo "${APT_ENV[@]}" apt-get install -y "python${PYVER}-venv"
      "$PY" -m venv "$VENV" || fail "Could not create the Python environment."
    fi
  else
    say "The system Python is older than 3.10. Setting up Python 3.12 for hunter-ai only."
    ensure_uv
    uv python install 3.12 || fail "Python 3.12 could not be downloaded."
    uv venv --seed --python 3.12 "$VENV" || fail "Could not create the Python environment."
  fi
fi
py_ok "$VENV/bin/python" || fail "The Python environment in $VENV is not working."
"$VENV/bin/python" -m pip install --quiet --upgrade pip
"$VENV/bin/python" -m pip install --quiet -r "$REPO_DIR/requirements.txt"

# --- 3. Claude Code (the agent runtime) ---------------------------------
if ! command -v claude >/dev/null 2>&1; then
  say "Installing Claude Code"
  if ! curl -fsSL https://claude.ai/install.sh | bash; then
    fail "Claude Code could not be downloaded from claude.ai. Check the internet connection and run the installer again."
  fi
fi
command -v claude >/dev/null 2>&1 || fail "Claude Code could not be installed."

# --- 4. The hunt / hk commands ------------------------------------------
mkdir -p "$HOME/.local/bin"
chmod +x "$REPO_DIR/bin/hunt" "$REPO_DIR/bin/hk"
ln -sf "$REPO_DIR/bin/hunt" "$HOME/.local/bin/hunt"
# hk is the inventory/scope toolkit the operator uses between phases (hk scope,
# hk candidates, hk candidate recheck, ...). It must be on PATH too.
ln -sf "$REPO_DIR/bin/hk" "$HOME/.local/bin/hk"
if ! grep -qs 'hunter-ai: PATH' "$HOME/.bashrc"; then
  # shellcheck disable=SC2016  # $HOME and $PATH must stay literal in .bashrc
  printf '\n# hunter-ai: PATH\nexport PATH="$HOME/.local/bin:$PATH"\n' >> "$HOME/.bashrc"
fi
mkdir -p "$HOME/.config/hunter-ai" "$HOME/targets"
chmod 700 "$HOME/.config/hunter-ai"

# --- 5. Recon tools (best effort) ---------------------------------------
say "Installing the recon tools (subfinder, dnsx, naabu, httpx, katana, ffuf)"
"$REPO_DIR/bin/hunt" tools install || say "Some recon tools did not install. Run later: hunt tools install"
# Arjun for HTTP parameter discovery (best effort; the fuzzing phase falls back
# to a params wordlist if it is missing).
if "$VENV/bin/python" -m pip install --quiet arjun 2>/dev/null; then
  ln -sf "$VENV/bin/arjun" "$HOME/.local/bin/arjun" 2>/dev/null || true
else
  say "arjun not installed (optional; parameter discovery falls back to a wordlist)."
fi

# Headless browser (Playwright Chromium) for the client-side testing phases:
# DOM/stored/postMessage/window.name PoCs that curl cannot show. Best effort -
# the phases note it is unavailable and fall back to curl if this fails.
chmod +x "$REPO_DIR/bin/hbrowse" 2>/dev/null || true
ln -sf "$REPO_DIR/bin/hbrowse" "$HOME/.local/bin/hbrowse" 2>/dev/null || true
say "Installing the headless browser (Playwright Chromium)"
# The browser binary downloads as the current user; its system libraries need the
# OS package manager (root). Do them separately so a non-root run still gets the
# browser and only the one root step is left.
if "$VENV/bin/python" -m playwright install chromium >/dev/null 2>&1; then
  if [ "$(id -u)" = "0" ]; then
    "$VENV/bin/python" -m playwright install-deps chromium >/dev/null 2>&1 \
      && say "Headless browser ready." \
      || say "Headless browser downloaded (its system libraries could not be installed - see 'hunt doctor')."
  elif command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null \
       && sudo "$VENV/bin/python" -m playwright install-deps chromium >/dev/null 2>&1; then
    say "Headless browser ready."
  elif "$VENV/bin/python" -m playwright install-deps chromium >/dev/null 2>&1; then
    say "Headless browser ready."
  else
    say "Headless browser downloaded. ONE root step is left - run once as root:"
    say "  $VENV/bin/python -m playwright install-deps chromium"
  fi
else
  say "Headless browser could not be downloaded. Check 'hunt doctor'; if it says the"
  say "OS is unsupported, the playwright pin in requirements.txt needs adjusting."
fi

# --- 6. Self-check ------------------------------------------------------
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

#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WITH_CTF=1
WITH_HEAVY=0
WITH_PROJECT=1
CHECK_ONLY=0
ASSUME_YES=1

usage() {
  cat <<'EOF'
Usage: scripts/install-env.sh [options]

Install development and CTF tooling for this OpenAgent workspace.

Options:
  --base-only       Install only base dev tools and project dependencies.
  --ctf            Install CTF tools. This is the default.
  --heavy          Also install heavy reverse/solver Python packages such as angr.
  --no-project     Do not run bun install.
  --check-only     Only print missing commands; do not install anything.
  --no-yes         Do not pass automatic yes flags to system package managers.
  -h, --help       Show this help.

Examples:
  bash scripts/install-env.sh
  bash scripts/install-env.sh --base-only
  bash scripts/install-env.sh --heavy
  bash scripts/install-env.sh --check-only
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --base-only)
      WITH_CTF=0
      ;;
    --ctf)
      WITH_CTF=1
      ;;
    --heavy)
      WITH_HEAVY=1
      WITH_CTF=1
      ;;
    --no-project)
      WITH_PROJECT=0
      ;;
    --check-only)
      CHECK_ONLY=1
      ;;
    --no-yes)
      ASSUME_YES=0
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage
      exit 2
      ;;
  esac
  shift
done

log() {
  printf '\n==> %s\n' "$*"
}

warn() {
  printf 'WARN: %s\n' "$*" >&2
}

has() {
  command -v "$1" >/dev/null 2>&1
}

sudo_cmd() {
  if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
    "$@"
  elif has sudo; then
    sudo "$@"
  else
    warn "sudo not found; cannot run privileged command: $*"
    return 1
  fi
}

pm_yes_flag() {
  [[ "$ASSUME_YES" -eq 1 ]] && printf '%s' "-y"
}

detect_pm() {
  if has apt-get; then echo apt; return; fi
  if has dnf; then echo dnf; return; fi
  if has pacman; then echo pacman; return; fi
  if has brew; then echo brew; return; fi
  echo unknown
}

PM="$(detect_pm)"

APT_UPDATED=0
apt_update_once() {
  if [[ "$APT_UPDATED" -eq 0 ]]; then
    sudo_cmd apt-get update
    APT_UPDATED=1
  fi
}

install_required_packages() {
  local label="$1"
  shift
  [[ $# -eq 0 ]] && return 0
  log "Installing required packages: $label"
  local yes
  yes="$(pm_yes_flag)"
  case "$PM" in
    apt)
      apt_update_once
      if [[ -n "$yes" ]]; then
        sudo_cmd apt-get install "$yes" "$@"
      else
        sudo_cmd apt-get install "$@"
      fi
      ;;
    dnf)
      if [[ -n "$yes" ]]; then
        sudo_cmd dnf install "$yes" "$@"
      else
        sudo_cmd dnf install "$@"
      fi
      ;;
    pacman)
      if [[ "$ASSUME_YES" -eq 1 ]]; then
        sudo_cmd pacman -S --needed --noconfirm "$@"
      else
        sudo_cmd pacman -S --needed "$@"
      fi
      ;;
    brew)
      brew install "$@"
      ;;
    *)
      warn "Unsupported package manager; install manually: $*"
      return 1
      ;;
  esac
}

try_install_package() {
  local pkg="$1"
  local yes
  yes="$(pm_yes_flag)"
  case "$PM" in
    apt)
      apt_update_once
      if [[ -n "$yes" ]]; then
        sudo_cmd apt-get install "$yes" "$pkg" >/dev/null 2>&1 || return 1
      else
        sudo_cmd apt-get install "$pkg" >/dev/null 2>&1 || return 1
      fi
      ;;
    dnf)
      if [[ -n "$yes" ]]; then
        sudo_cmd dnf install "$yes" "$pkg" >/dev/null 2>&1 || return 1
      else
        sudo_cmd dnf install "$pkg" >/dev/null 2>&1 || return 1
      fi
      ;;
    pacman)
      if [[ "$ASSUME_YES" -eq 1 ]]; then
        sudo_cmd pacman -S --needed --noconfirm "$pkg" >/dev/null 2>&1 || return 1
      else
        sudo_cmd pacman -S --needed "$pkg" >/dev/null 2>&1 || return 1
      fi
      ;;
    brew)
      brew install "$pkg" >/dev/null 2>&1 || return 1
      ;;
    *)
      return 1
      ;;
  esac
}

try_install_any() {
  local label="$1"
  shift
  for pkg in "$@"; do
    if try_install_package "$pkg"; then
      echo "installed $label via package: $pkg"
      return 0
    fi
  done
  warn "Could not install optional package '$label'. Tried: $*"
  return 1
}

base_packages_for_pm() {
  case "$PM" in
    apt)
      echo ca-certificates curl git make gcc g++ pkg-config python3 python3-pip python3-venv nodejs file binutils jq ripgrep
      ;;
    dnf)
      echo ca-certificates curl git make gcc gcc-c++ pkgconf-pkg-config python3 python3-pip nodejs file binutils jq ripgrep
      ;;
    pacman)
      echo ca-certificates curl git base-devel pkgconf python python-pip nodejs file binutils jq ripgrep
      ;;
    brew)
      echo curl git make pkg-config python node binutils jq ripgrep
      ;;
  esac
}

ctf_packages_for_pm() {
  case "$PM" in
    apt)
      echo gdb patchelf ruby ruby-dev socat strace unzip zip xz-utils
      ;;
    dnf)
      echo gdb patchelf ruby ruby-devel socat strace unzip zip xz
      ;;
    pacman)
      echo gdb patchelf ruby socat strace unzip zip xz
      ;;
    brew)
      echo gdb patchelf ruby socat binutils
      ;;
  esac
}

install_bun_if_missing() {
  if has bun; then
    echo "bun found: $(command -v bun)"
    return 0
  fi
  log "Installing Bun"
  curl -fsSL https://bun.sh/install | bash
  export PATH="$HOME/.bun/bin:$PATH"
  if ! has bun; then
    warn "Bun installer finished, but bun is not on PATH. Add ~/.bun/bin to PATH and rerun."
    return 1
  fi
}

pip_install_user() {
  if ! has python3; then
    warn "python3 not found; skipping Python package install"
    return 1
  fi

  python3 -m pip install --user --upgrade "$@" || \
    python3 -m pip install --user --break-system-packages --upgrade "$@"
  export PATH="$HOME/.local/bin:$PATH"
}

gem_user_bin() {
  ruby -e 'require "rubygems"; print File.join(Gem.user_dir, "bin")' 2>/dev/null || true
}

install_one_gadget() {
  if has one_gadget; then
    echo "one_gadget found: $(command -v one_gadget)"
    return 0
  fi
  if ! has gem; then
    warn "gem not found; skipping one_gadget"
    return 1
  fi

  log "Installing one_gadget"
  gem install --user-install one_gadget --no-document || sudo_cmd gem install one_gadget --no-document || true
  local bin
  bin="$(gem_user_bin)"
  if [[ -n "$bin" ]]; then
    export PATH="$bin:$PATH"
  fi
}

install_python_ctf_packages() {
  log "Installing Python CTF packages"
  pip_install_user \
    pwntools \
    ROPGadget \
    ropper \
    z3-solver \
    unicorn \
    capstone \
    pycryptodome \
    requests

  if [[ "$WITH_HEAVY" -eq 1 ]]; then
    log "Installing heavy reverse/solver Python packages"
    pip_install_user angr angrop
  fi
}

install_system_packages() {
  if [[ "$PM" == unknown ]]; then
    warn "No supported package manager found. Supported: apt-get, dnf, pacman, brew."
    return 0
  fi

  # shellcheck disable=SC2046
  install_required_packages "base" $(base_packages_for_pm)

  if [[ "$WITH_CTF" -eq 1 ]]; then
    # shellcheck disable=SC2046
    install_required_packages "ctf" $(ctf_packages_for_pm)

    try_install_any checksec checksec || true
    try_install_any ltrace ltrace || true

    case "$PM" in
      apt)
        try_install_any upx upx-ucl upx || true
        try_install_any netcat netcat-openbsd netcat-traditional || true
        try_install_any radare2 radare2 || true
        try_install_any rizin rizin || true
        try_install_any binwalk binwalk || true
        ;;
      dnf)
        try_install_any upx upx || true
        try_install_any ncat nmap-ncat nc || true
        try_install_any radare2 radare2 || true
        try_install_any rizin rizin || true
        try_install_any binwalk binwalk || true
        ;;
      pacman)
        try_install_any upx upx || true
        try_install_any netcat openbsd-netcat gnu-netcat || true
        try_install_any radare2 radare2 || true
        try_install_any rizin rizin || true
        try_install_any binwalk binwalk || true
        ;;
      brew)
        try_install_any upx upx || true
        try_install_any netcat netcat || true
        try_install_any radare2 radare2 || true
        try_install_any rizin rizin || true
        try_install_any binwalk binwalk || true
        ;;
    esac
  fi
}

run_project_install() {
  [[ "$WITH_PROJECT" -eq 1 ]] || return 0
  log "Installing workspace dependencies"
  cd "$ROOT_DIR"
  bun install
}

missing_commands() {
  local missing=0
  local base=(git curl bun node make python3 file strings readelf objdump)
  local ctf=(gdb checksec patchelf upx ROPgadget ropper one_gadget)

  echo "Base commands:"
  for cmd in "${base[@]}"; do
    if has "$cmd"; then
      printf '  [ok]      %s -> %s\n' "$cmd" "$(command -v "$cmd")"
    else
      printf '  [missing] %s\n' "$cmd"
      missing=1
    fi
  done

  if [[ "$WITH_CTF" -eq 1 ]]; then
    echo "CTF commands:"
    for cmd in "${ctf[@]}"; do
      if has "$cmd"; then
        printf '  [ok]      %s -> %s\n' "$cmd" "$(command -v "$cmd")"
      else
        printf '  [missing] %s\n' "$cmd"
        missing=1
      fi
    done

    echo "CTF Python imports:"
    for mod in pwn z3 unicorn capstone Crypto; do
      if python3 - "$mod" <<'PY' >/dev/null 2>&1
import importlib
import sys
importlib.import_module(sys.argv[1])
PY
      then
        printf '  [ok]      import %s\n' "$mod"
      else
        printf '  [missing] import %s\n' "$mod"
        missing=1
      fi
    done
  fi

  return "$missing"
}

print_path_notes() {
  cat <<EOF

PATH notes:
  - Bun binaries usually live in: ~/.bun/bin
  - pip --user scripts usually live in: ~/.local/bin
  - Ruby user gems may live in: $(gem_user_bin || true)

If a command was installed but still appears missing, add these directories to PATH.
Example:
  export PATH="\$HOME/.bun/bin:\$HOME/.local/bin:\$PATH"
EOF
}

main() {
  log "OpenAgent environment installer"
  echo "Root: $ROOT_DIR"
  echo "Package manager: $PM"
  echo "CTF tools: $WITH_CTF"
  echo "Heavy tools: $WITH_HEAVY"
  echo "Project install: $WITH_PROJECT"

  export PATH="$HOME/.bun/bin:$HOME/.local/bin:$PATH"
  local gem_bin
  gem_bin="$(gem_user_bin || true)"
  if [[ -n "$gem_bin" ]]; then
    export PATH="$gem_bin:$PATH"
  fi

  if [[ "$CHECK_ONLY" -eq 1 ]]; then
    log "Checking installed commands"
    missing_commands || true
    print_path_notes
    exit 0
  fi

  install_system_packages
  install_bun_if_missing

  if [[ "$WITH_CTF" -eq 1 ]]; then
    install_python_ctf_packages
    install_one_gadget
  fi

  run_project_install

  log "Final tool check"
  missing_commands || true
  print_path_notes

  cat <<'EOF'

Done.

Next steps:
  bun run dev
  make deploy
  openagent --agent ctf
EOF
}

main "$@"

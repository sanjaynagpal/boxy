#!/usr/bin/env bash
# Create a Python 3.12 virtualenv with ansible-core 2.16 in $BOXY_VENV
# (default ~/bx-ansible), without sudo. Uses the standalone `uv` release
# binary, because distro Pythons newer than 3.12 are not supported by
# ansible-core 2.16 and python3-venv may not be installed.
#
# Run inside WSL/Ubuntu:   tests/integration/setup-wsl.sh
set -euo pipefail

VENV="${BOXY_VENV:-$HOME/bx-ansible}"
UVDIR="${BOXY_UV_DIR:-$HOME/uvbin}"

if [ ! -x "$UVDIR/uv" ]; then
  mkdir -p "$UVDIR"
  curl -fsSL -o "$UVDIR/uv.tgz" \
    https://github.com/astral-sh/uv/releases/latest/download/uv-x86_64-unknown-linux-gnu.tar.gz
  tar xzf "$UVDIR/uv.tgz" -C "$UVDIR" --strip-components=1
  rm -f "$UVDIR/uv.tgz"
fi

"$UVDIR/uv" venv --python 3.12 "$VENV"
"$UVDIR/uv" pip install -q --python "$VENV/bin/python" "ansible-core==2.16.*"
"$VENV/bin/ansible" --version | head -1
echo "ready: BOXY_VENV=$VENV tests/integration/run.sh"

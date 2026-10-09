#!/usr/bin/env bash
# Install sops, age and the community.sops collection into $BOXY_TOOLS
# (default ~/bx-tools) without sudo, for tests/integration/sops.sh.
# Needs the ansible virtualenv from setup-wsl.sh (BOXY_VENV, default ~/bx-ansible).
set -euo pipefail

TOOLS="${BOXY_TOOLS:-$HOME/bx-tools}"
VENV="${BOXY_VENV:-$HOME/bx-ansible}"
mkdir -p "$TOOLS/bin"
cd "$TOOLS"

latest() { # latest <github-owner/repo>
  curl -fsSL "https://api.github.com/repos/$1/releases/latest" |
    python3 -c 'import sys, json; print(json.load(sys.stdin)["tag_name"])'
}

SOPS_TAG="$(latest getsops/sops)"
AGE_TAG="$(latest FiloSottile/age)"
curl -fsSL -o bin/sops "https://github.com/getsops/sops/releases/download/$SOPS_TAG/sops-$SOPS_TAG.linux.amd64"
curl -fsSL -o age.tgz "https://github.com/FiloSottile/age/releases/download/$AGE_TAG/age-$AGE_TAG-linux-amd64.tar.gz"
tar xzf age.tgz
cp age/age age/age-keygen bin/
rm -rf age age.tgz
chmod +x bin/*

PATH="$TOOLS/bin:$VENV/bin:$PATH"
"$VENV/bin/ansible-galaxy" collection install community.sops -p "$TOOLS/collections"
sops --version | head -1
age --version
echo "ready: tests/integration/sops.sh"

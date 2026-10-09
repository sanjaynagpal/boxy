#!/usr/bin/env bash
# End-to-end test of sanjaynagpal.boxcar.unbox against localhost
# (connection: local) using a real ansible-core.
#
# Run on a Linux filesystem (file modes are asserted, so not /mnt/c):
#   tests/integration/setup-wsl.sh      # once
#   tests/integration/run.sh
# Override the virtualenv with BOXY_VENV (default ~/bx-ansible).
#
# The repo is copied to a temp dir, so nothing in the checkout is modified.
# The password and key material below are throwaway test values.
set -uo pipefail

VENV="${BOXY_VENV:-$HOME/bx-ansible}"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
export PATH="$VENV/bin:$PATH"
command -v ansible-playbook >/dev/null || { echo "ansible-playbook not found; run setup-wsl.sh" >&2; exit 2; }

W="$(mktemp -d)"
trap 'rm -rf "$W"' EXIT
cp -r "$REPO/collections" "$REPO/tools" "$W/"
cd "$W"

PW="correct horse battery"
KEYTEXT="SECRETKEYMATERIAL"
fails=0
pass() { echo "  ok   $1"; }
fail() { echo "  FAIL $1"; fails=$((fails + 1)); }
check() { # check <description> <command...>
  local d="$1"; shift
  if "$@" >/dev/null 2>&1; then pass "$d"; else fail "$d"; fi
}
run() { ansible-playbook "$@" 2>&1; }
vars() { printf '{"out": "%s", "pw": "%s"}' "$1" "${2:-$PW}" > "$W/v.json"; echo "@$W/v.json"; }

mkdir -p src/pki
printf -- "-----BEGIN PRIVATE KEY-----\n%s\n-----END PRIVATE KEY-----\n" "$KEYTEXT" > src/server.key
printf -- "-----BEGIN CERTIFICATE-----\nCERTBODY\n-----END CERTIFICATE-----\n" > src/pki/server.crt
cat > ansible.cfg <<EOF
[defaults]
collections_path = ./collections
localhost_warning = False
interpreter_python = auto_silent
EOF
cat > play.yml <<'EOF'
- hosts: localhost
  connection: local
  gather_facts: false
  tasks:
    - sanjaynagpal.boxcar.unbox:
        src: "{{ bundle | default('tls.box') }}"
        dest: "{{ out }}"
        password: "{{ pw | default(omit) }}"
        entries: "{{ only | default(omit) }}"
      no_log: "{{ nolog | default(true) }}"
EOF

echo "== seal"
export BOXCAR_PASSWORD="$PW"
python3 tools/ansible-boxcar seal tls.box src --mode '*.crt=0644' >/dev/null
check "list shows names and modes" bash -c "python3 tools/ansible-boxcar list tls.box | grep -q '^0644  pki/server.crt' && python3 tools/ansible-boxcar list tls.box | grep -q '^0600  server.key'"
unset BOXCAR_PASSWORD

echo "== local unbox (CLI)"
BOXCAR_PASSWORD="$PW" python3 tools/ansible-boxcar unbox tls.box cli1 >/dev/null
check "CLI unbox restores content" grep -q "$KEYTEXT" cli1/server.key
check "CLI unbox key mode 0600" test "$(stat -c %a cli1/server.key)" = 600
check "CLI unbox cert mode 0644" test "$(stat -c %a cli1/pki/server.crt)" = 644
check "CLI unbox refuses to overwrite" bash -c '! BOXCAR_PASSWORD="$0" python3 tools/ansible-boxcar unbox tls.box cli1' "$PW"
check "CLI unbox wrong password writes nothing" bash -c '! BOXCAR_PASSWORD=wrong-password-x python3 tools/ansible-boxcar unbox tls.box cli2 && test ! -e cli2'

echo "== install"
out="$(run play.yml -e "$(vars "$W/o1")")"
check "first run succeeds with changes" grep -q 'changed=1 .*failed=0' <<<"$out"
check "key mode 0600" test "$(stat -c %a o1/server.key)" = 600
check "cert mode 0644" test "$(stat -c %a o1/pki/server.crt)" = 644
check "directory mode 0700" test "$(stat -c %a o1/pki)" = 700
check "content intact" grep -q "$KEYTEXT" o1/server.key

echo "== idempotency and repair"
check "second run changes nothing" grep -q 'changed=0 ' <<<"$(run play.yml -e "$(vars "$W/o1")")"
echo tampered > o1/server.key; chmod 644 o1/server.key
check "tampered file reported changed" grep -q 'changed=1 ' <<<"$(run play.yml -e "$(vars "$W/o1")")"
check "tampered file repaired (content+mode)" bash -c "grep -q $KEYTEXT o1/server.key && test \$(stat -c %a o1/server.key) = 600"

echo "== failure paths write nothing"
out="$(run play.yml -e "$(vars "$W/o2" "wrong password!")")"
check "wrong password fails" grep -q 'failed=1' <<<"$out"
check "wrong password creates no dest" test ! -e o2
python3 - <<'EOF'
import json
d = json.load(open("tls.box"))
for e in d["entries"]:
    if e["name"] == "server.key":
        e["mode"] = "0644"
json.dump(d, open("tampered.box", "w"))
EOF
out="$(run play.yml -e "$(vars "$W/o3")" -e bundle=tampered.box -e nolog=false)"
check "tampered bundle mode is rejected" grep -q 'incorrect password or corrupted' <<<"$out"
check "tampered bundle creates no dest" test ! -e o3
out="$(run play.yml -e "$(vars "$W/o4")" -e nolog=false --diff)"
check "--diff refused" grep -q 'refuses to run with --diff' <<<"$out"
check "--diff creates no dest" test ! -e o4
head -c 64 /dev/urandom > blob.bin
BOXCAR_PASSWORD="$PW" python3 tools/ansible-boxcar seal bin.box blob.bin >/dev/null
out="$(run play.yml -e "$(vars "$W/o5")" -e bundle=bin.box -e nolog=false)"
check "binary entry rejected" grep -q 'only supports text entries' <<<"$out"
check "binary rejection creates no dest" test ! -e o5

echo "== options"
out="$(run play.yml -e "$(vars "$W/o6")" --check)"
check "check mode succeeds" grep -q 'failed=0' <<<"$out"
check "check mode writes nothing" test ! -e o6
printf '{"out": "%s", "pw": "%s", "only": ["pki/server.crt"]}' "$W/o7" "$PW" > v2.json
run play.yml -e @v2.json >/dev/null
check "entries filter installs only the selected file" bash -c "test -f o7/pki/server.crt && test ! -e o7/server.key"
printf '{"out": "%s", "pw": "%s", "only": ["nope"]}' "$W/o8" "$PW" > v3.json
check "unknown entry rejected" grep -q 'not in bundle: nope' <<<"$(run play.yml -e @v3.json -e nolog=false)"
printf '{"out": "%s"}' "$W/o9" > v4.json
BOXCAR_PASSWORD="$PW" run play.yml -e @v4.json >/dev/null
check "BOXCAR_PASSWORD fallback" test -f o9/server.key
check "no password anywhere is an error" grep -q 'no password' <<<"$(run play.yml -e @v4.json -e nolog=false)"

echo "== secrets do not leak"
log="$(run play.yml -e "$(vars "$W/o10")" -e nolog=false -vvv)"
check "no key material in -vvv output" bash -c '! grep -q "$0" <<<"$1"' "$KEYTEXT" "$log"
check "no CERTBODY in -vvv output" bash -c '! grep -q CERTBODY <<<"$0"' "$log"
check "no password in -vvv output" bash -c '! grep -q "$0" <<<"$1"' "$PW" "$log"
check "no plaintext left in ansible temp dirs" bash -c "! grep -rqs $KEYTEXT \$HOME/.ansible/tmp /tmp --exclude-dir=$(basename "$W")"

echo "== vars_prompt (pty)"
cat > prompt.yml <<'EOF'
- hosts: localhost
  connection: local
  gather_facts: false
  vars_prompt:
    - name: boxcar_password
      prompt: Bundle password
      private: true
  tasks:
    - sanjaynagpal.boxcar.unbox:
        src: tls.box
        dest: "{{ playbook_dir }}/o11"
        password: "{{ boxcar_password }}"
      no_log: true
EOF
PW="$PW" python3 - <<'EOF'
import os, pty, time
pid, fd = pty.fork()
if pid == 0:
    os.execvp("ansible-playbook", ["ansible-playbook", "prompt.yml"])
buf, sent = b"", False
while True:
    try:
        chunk = os.read(fd, 4096)
    except OSError:
        break
    if not chunk:
        break
    buf += chunk
    if not sent and b"Bundle password" in buf:
        time.sleep(0.3)
        os.write(fd, os.environ["PW"].encode() + b"\n")
        sent = True
_, status = os.waitpid(pid, 0)
open("prompt.exit", "w").write(str(os.waitstatus_to_exitcode(status)))
open("prompt.out", "wb").write(buf.split(b"Bundle password", 1)[1])
EOF
check "prompt run exits 0" test "$(cat prompt.exit)" = 0
check "prompted run installs files" test -f o11/server.key
check "password not echoed" bash -c '! grep -q "$0" prompt.out' "$PW"

echo
if [ "$fails" -eq 0 ]; then echo "ALL PASSED"; else echo "$fails FAILED"; exit 1; fi

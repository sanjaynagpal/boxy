#!/usr/bin/env bash
# End-to-end test of examples/sops-combined: a boxcar bundle whose password is
# held in a SOPS(age)-encrypted file, so nobody types or exports it.
#
#   tests/integration/setup-wsl.sh        # ansible-core (once)
#   tests/integration/setup-sops-wsl.sh   # sops, age, community.sops (once)
#   tests/integration/sops.sh
#
# Runs against localhost (connection: local) in a temp copy of the repo.
# All keys and passwords below are generated for the test and discarded.
set -uo pipefail

VENV="${BOXY_VENV:-$HOME/bx-ansible}"
TOOLS="${BOXY_TOOLS:-$HOME/bx-tools}"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
export PATH="$TOOLS/bin:$VENV/bin:$PATH"
for c in ansible-playbook sops age-keygen; do
  command -v "$c" >/dev/null || { echo "$c not found; run setup-wsl.sh and setup-sops-wsl.sh" >&2; exit 2; }
done

W="$(mktemp -d)"
trap 'rm -rf "$W"' EXIT
cp -r "$REPO/collections" "$REPO/tools" "$W/"
mkdir -p "$W/examples" && cp -r "$REPO/examples/sops-combined" "$W/examples/"
cd "$W/examples/sops-combined"
mkdir -p collections && cp -r "$TOOLS/collections/ansible_collections" collections/ 2>/dev/null
# boxcar collection from the repo copy; community.sops from the tools dir.
cat > ansible.cfg <<EOF
[defaults]
collections_path = ./collections:$W/collections
localhost_warning = False
interpreter_python = auto_silent
EOF

fails=0
pass() { echo "  ok   $1"; }
fail() { echo "  FAIL $1"; fails=$((fails + 1)); }
check() { local d="$1"; shift; if "$@" >/dev/null 2>&1; then pass "$d"; else fail "$d"; fi; }

echo "== setup: three age identities (operator, CI job, outsider)"
for who in operator ci outsider; do age-keygen -o "$W/$who.key" 2>/dev/null; chmod 600 "$W/$who.key"; done
pub() { age-keygen -y "$W/$1.key"; }
sed -i "s/age1REPLACE_WITH_OPERATOR_PUBLIC_KEY/$(pub operator)/; s/age1REPLACE_WITH_CI_JOB_PUBLIC_KEY/$(pub ci)/" .sops.yaml

echo "== seal with a GENERATED password, store it only in SOPS"
PW="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
mkdir -p src/pki
printf -- "-----BEGIN PRIVATE KEY-----\nSECRETKEYMATERIAL\n-----END PRIVATE KEY-----\n" > src/server.key
printf -- "-----BEGIN CERTIFICATE-----\nCERTBODY\n-----END CERTIFICATE-----\n" > src/pki/server.crt
BOXCAR_PASSWORD="$PW" python3 "$W/tools/ansible-boxcar" seal files/tls.box src --mode '*.crt=0644' >/dev/null
printf 'boxcar_password: "%s"\n' "$PW" |
  sops --encrypt --filename-override files/bundle-password.sops.yaml \
       --input-type yaml --output-type yaml /dev/stdin > files/bundle-password.sops.yaml
rm -rf src
check "password file is SOPS-encrypted (no plaintext password)" bash -c '! grep -q "$0" files/bundle-password.sops.yaml' "$PW"
check "bundle has no plaintext key material" bash -c '! grep -q SECRETKEYMATERIAL files/tls.box'

run() { ansible-playbook deploy.yml -i 'localhost,' -c local \
          -e target=localhost -e use_become=false -e "tls_dest=$1" "${@:2}" 2>&1; }

echo "== deploy with NO prompt and NO BOXCAR_PASSWORD"
unset BOXCAR_PASSWORD
for who in operator ci; do
  out="$(SOPS_AGE_KEY_FILE="$W/$who.key" run "$W/out-$who")"
  check "$who key deploys" grep -q 'changed=1 .*failed=0' <<<"$out"
  check "$who: key file content intact, mode 0600" bash -c "grep -q SECRETKEYMATERIAL '$W/out-$who/server.key' && test \$(stat -c %a '$W/out-$who/server.key') = 600"
  check "$who: cert mode 0644 in subdirectory" test "$(stat -c %a "$W/out-$who/pki/server.crt")" = 644
done
check "re-run is idempotent" grep -q 'changed=0 ' <<<"$(SOPS_AGE_KEY_FILE="$W/ci.key" run "$W/out-ci")"

echo "== outsider (not a recipient) is refused and nothing is written"
out="$(SOPS_AGE_KEY_FILE="$W/outsider.key" run "$W/out-outsider" -e nolog=false)"
check "outsider deploy fails" grep -q 'failed=1' <<<"$out"
check "outsider writes nothing" test ! -e "$W/out-outsider"

echo "== no key available at all"
out="$(SOPS_AGE_KEY_FILE=/nonexistent run "$W/out-nokey")"
check "missing age key fails" grep -q 'failed=1' <<<"$out"
check "missing age key writes nothing" test ! -e "$W/out-nokey"

echo "== secrets do not leak (-vvv)"
log="$(SOPS_AGE_KEY_FILE="$W/operator.key" run "$W/out-vvv" -vvv)"
check "no bundle password in output" bash -c '! grep -q "$0" <<<"$1"' "$PW" "$log"
check "no key material in output" bash -c '! grep -q SECRETKEYMATERIAL <<<"$0"' "$log"

echo "== password rotation: re-seal + re-encrypt, old bundle/password file pair no longer mixes"
PW2="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
cp files/tls.box old.box
OLD="$(SOPS_AGE_KEY_FILE="$W/operator.key" sops -d --extract '["boxcar_password"]' files/bundle-password.sops.yaml)"
check "documented sops -d --extract returns the stored password" test "$OLD" = "$PW"
mkdir -p src2 && BOXCAR_PASSWORD="$OLD" python3 "$W/tools/ansible-boxcar" unbox old.box src2 >/dev/null
BOXCAR_PASSWORD="$PW2" python3 "$W/tools/ansible-boxcar" seal files/tls.box src2 --force >/dev/null
check "stale password file cannot open the re-sealed bundle" grep -q 'failed=1' <<<"$(SOPS_AGE_KEY_FILE="$W/operator.key" run "$W/out-rot")"
printf 'boxcar_password: "%s"\n' "$PW2" |
  sops --encrypt --filename-override files/bundle-password.sops.yaml \
       --input-type yaml --output-type yaml /dev/stdin > files/bundle-password.sops.yaml
check "after updating the password file, deploy works" grep -q 'failed=0' <<<"$(SOPS_AGE_KEY_FILE="$W/operator.key" run "$W/out-rot")"

echo
if [ "$fails" -eq 0 ]; then echo "ALL PASSED"; else echo "$fails FAILED"; exit 1; fi

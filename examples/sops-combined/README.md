# Example: boxcar bundle + SOPS-held password

**Problem:** with a plain bundle, someone must choose a strong password and
keep it somewhere (a CI secret, a password manager). **This example removes
both:** the bundle password is *generated*, never typed, and stored only in a
[SOPS](https://github.com/getsops/sops)-encrypted file that each authorised
person or CI job opens with **its own age key**.

| Piece | Does | Needs |
|---|---|---|
| `ansible-boxcar` bundle (`files/tls.box`) | holds the key/cert files, installs them with modes and owners | `cryptography` |
| SOPS file (`files/bundle-password.sops.yaml`) | holds the bundle password, readable only by listed age keys | `sops` binary, `community.sops` collection |
| `deploy.yml` | reads the password with the SOPS lookup, passes it to `unbox` | both of the above |

Nothing is prompted and no `BOXCAR_PASSWORD` is exported. Who can deploy is
decided by the recipient list in `.sops.yaml`.

## One-time setup

```bash
# 1. Each person / CI job makes an age key and shares only the PUBLIC key.
age-keygen -o ~/.config/sops/age/keys.txt        # prints: Public key: age1...

# 2. Put the public keys in .sops.yaml (replace the age1REPLACE_... placeholders).

# 3. Install the lookup collection next to the playbook.
ansible-galaxy collection install community.sops -p ./collections
```

## Seal (operator, whenever the certificate or key changes)

```bash
# --generate makes a strong random password (nobody types or invents it) and prints
# only that password on stdout; status messages go to stderr.
PW="$(../../tools/ansible-boxcar seal files/tls.box ./certs --mode '*.crt=0644' --generate)"

printf 'boxcar_password: "%s"\n' "$PW" |
  sops --encrypt --filename-override files/bundle-password.sops.yaml \
       --input-type yaml --output-type yaml /dev/stdin > files/bundle-password.sops.yaml
unset PW
```

Both `files/tls.box` and `files/bundle-password.sops.yaml` are safe to commit.
The plaintext password exists only in that shell variable while you run the
two commands.

## Deploy

```bash
export SOPS_AGE_KEY_FILE=~/.config/sops/age/keys.txt   # this person's / job's own key
ansible-playbook -i inventory.ini deploy.yml
```

Override defaults with `-e target=... -e tls_dest=/etc/pki/app -e tls_owner=root -e tls_group=ssl-cert`.

## Day-two operations

| Task | How |
|---|---|
| Add a person or CI job | Add their public key to `.sops.yaml`, then `sops updatekeys files/bundle-password.sops.yaml`. |
| Remove someone | Remove their key, `sops updatekeys ...`, **then rotate the password** (below): they may still hold an old copy of the file. |
| Rotate the bundle password | Unbox to a protected folder (`ansible-boxcar unbox`), re-seal with a new generated password and `--force`, re-encrypt the SOPS file. Commit both files together: a new bundle with the old password file fails closed. |

### Rotation, step by step

```bash
OLD="$(sops -d --extract '["boxcar_password"]' files/bundle-password.sops.yaml)"
BOXCAR_PASSWORD="$OLD" ../../tools/ansible-boxcar unbox files/tls.box ./work    # protected folder
NEW="$(../../tools/ansible-boxcar seal files/tls.box ./work --force --generate)"
printf 'boxcar_password: "%s"\n' "$NEW" |
  sops --encrypt --filename-override files/bundle-password.sops.yaml \
       --input-type yaml --output-type yaml /dev/stdin > files/bundle-password.sops.yaml
unset OLD NEW; rm -rf ./work
```

## Troubleshooting

`deploy.yml` uses `no_log: true`, which also hides *why* a task failed. To see
whether the SOPS step is the problem, test it directly:

```bash
SOPS_AGE_KEY_FILE=... sops -d files/bundle-password.sops.yaml
```

If that fails, your key is not a recipient (or the file was not found). If it
works but `unbox` fails with "incorrect password or corrupted bundle", the
bundle and the password file are from different seals.

## Notes

- `rstrip=false` in the lookup matters: the lookup trims trailing whitespace by
  default, which would silently alter a stored value.
- SOPS is used here only for the small password. The key/cert files stay in the
  bundle because `unbox` also sets their modes, owners and directories, and
  authenticates the modes.
- Keep age private keys out of Git and off shared hosts. A CI job's key should
  be its own, stored in that CI system's secret store.
- Tested on localhost with sops 3.13.3, age 1.3.2, community.sops 2.5.0,
  ansible-core 2.16 (`tests/integration/sops.sh`).

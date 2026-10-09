# User guide: protecting keys and certificates in Ansible with boxcar

This guide is for operators who distribute private keys, certificates and PEM
files to managed hosts with Ansible. It explains what the tool does, when to
use it, and how to run it, with worked examples.

- [What problem this solves](#what-problem-this-solves)
- [How it works](#how-it-works)
- [Requirements](#requirements)
- [Quick start](#quick-start)
- [Use cases](#use-cases)
- [Command and module reference](#command-and-module-reference)
- [Operating practices](#operating-practices)
- [Security notes and limits](#security-notes-and-limits)
- [Troubleshooting](#troubleshooting)

## What problem this solves

Your control node holds sensitive artifacts (TLS private keys, certificates,
client PEM files) on disk, and a playbook copies them to many hosts. Left as
plain files, anyone who can read the control node's filesystem, a backup of
it, or the Git repository holding the playbooks gets every key.

`ansible-boxcar` seals those files into one encrypted **bundle** protected by
a password only the operator knows. The bundle is safe to keep at rest and to
commit to Git. At deploy time the operator types the password once; the
`sanjaynagpal.boxcar.unbox` module decrypts the bundle on the control node and
installs the files on each host.

**Compared with `ansible-vault`:**

| | ansible-vault | boxcar bundle |
|---|---|---|
| Key derivation | PBKDF2, 10,000 iterations | scrypt (memory-hard), a stronger defence against offline password guessing |
| A folder of artifacts | one encrypted file per artifact | one bundle holding many named files |
| Binds file name and mode | no | yes, so renaming an entry or loosening its mode is detected |
| Installs with owner/mode/directories | via `copy` | built in, from the sealed modes |
| Integration | native everywhere | only the `unbox` module; vars and templates still use `ansible-vault` |

The two can be used together: keep ordinary variables in `ansible-vault` and
key/certificate files in a boxcar bundle.

## How it works

```
  operator                       control node                         managed hosts
  --------                       ------------                         -------------
  ansible-boxcar seal  ──►  tls.box (encrypted, at rest / in Git)
                                   │
  ansible-playbook  ── password ──►│  unbox: decrypt + verify ALL entries
  (prompted once)                  │       │
                                   │       └─► ansible.builtin.copy ──► /etc/pki/app/...
```

1. **Seal** (once, or whenever the artifacts change): files and folders are
   encrypted with AES-256-GCM under a key derived from your password.
2. **Unbox** (every deploy): the module decrypts on the control node, checks
   that every entry is authentic, and only then writes anything. A wrong
   password or a modified bundle changes nothing on any host.
3. Writing is done by `ansible.builtin.copy`, so files are replaced atomically
   and a re-run reports `changed` only when something actually differs.

## Requirements

- Control node: ansible-core **2.16**, Python **3.12**. The `cryptography`
  package is required and is already a dependency of ansible-core.
- Managed hosts: nothing extra. No boxcar software or password goes to them.
- The sealing tool runs wherever you have Python 3.12 and `cryptography`,
  normally the control node itself.

## Quick start

**1. Make the collection available.** In your project's `ansible.cfg`:

```ini
[defaults]
collections_path = ./collections
```

and copy (or clone) this repository's `collections/ansible_collections/`
directory into `./collections`. Alternatively copy the collection to
`~/.ansible/collections/ansible_collections/sanjaynagpal/boxcar`.

**2. Seal your files.** Put the artifacts in a folder, then:

```
tools/ansible-boxcar seal files/tls.box ./certs --mode '*.crt=0644'
```

You are prompted for a password twice. Every file defaults to mode `0600`; the
`--mode` option sets a different mode for names matching a pattern. Check the
result (no password needed):

```
$ tools/ansible-boxcar list files/tls.box
0644  pki/server.crt
0600  server.key
```

**3. Write the playbook** (`deploy-tls.yml`, next to the `files/` directory):

```yaml
- hosts: webservers
  become: true
  vars_prompt:
    - name: boxcar_password
      prompt: Bundle password
      private: true
  tasks:
    - name: Install TLS material
      sanjaynagpal.boxcar.unbox:
        src: tls.box                 # found in ./files/ beside the playbook
        dest: /etc/pki/app
        password: "{{ boxcar_password }}"
        owner: root
        group: ssl-cert
      no_log: true
```

**4. Run it.**

```
ansible-playbook deploy-tls.yml
Bundle password:
```

The password is not echoed. `src` is looked up like any role file: first in a
`files/` directory beside the playbook (or in the role), then as given.

## Use cases

### 1. Distribute a certificate and key to a web server fleet

*Situation:* 40 web servers need the same TLS certificate and private key. The
key must never sit unencrypted on the control node or in the repo.

*Do:* the quick start above. Seal `server.key` (mode `0600`) and `server.crt`
(mode `0644`) into `files/tls.box`, commit the bundle, and run the playbook
with `--limit` to roll out gradually:

```
ansible-playbook deploy-tls.yml --limit web01,web02
```

The password is prompted once for the whole play, however many hosts there
are.

### 2. Ship a whole PKI folder with a directory layout

*Situation:* an application needs a CA chain, a client certificate and a client
key arranged as `ca/chain.pem`, `client/client.crt`, `client/client.key`.

*Do:* seal the folder. Paths inside it are preserved relative to the folder
you give:

```
tools/ansible-boxcar seal files/app-pki.box ./app-pki \
    --mode 'client/client.key=0600' --mode '*=0644'
```

Order matters: the first matching `--mode` rule wins, so put specific
patterns before the catch-all `*`. Unboxing creates `ca/` and `client/` under
`dest` with `directory_mode` (default `0700`):

```yaml
- sanjaynagpal.boxcar.unbox:
    src: app-pki.box
    dest: /opt/app/pki
    password: "{{ boxcar_password }}"
    owner: app
    group: app
    directory_mode: "0750"
  no_log: true
```

### 3. Give different host groups different parts of one bundle

*Situation:* one bundle holds material for several roles, but each group of
hosts should receive only its own files.

*Do:* use `entries` to select by name:

```yaml
- hosts: db
  tasks:
    - sanjaynagpal.boxcar.unbox:
        src: platform.box
        dest: /etc/pki/db
        password: "{{ boxcar_password }}"
        entries: [db/server.crt, db/server.key]
      no_log: true
```

Entries not listed are decrypted on the control node (to verify the bundle)
but never sent to the host. If you ask for a name that is not in the bundle,
the task fails and writes nothing. Where groups must not even be able to
*see* each other's material, use separate bundles with separate passwords
(use case 5).

### 4. Update or rotate a certificate

*Situation:* the certificate renews every 90 days.

*Do:* re-seal with `--force`, then re-run the playbook:

```
tools/ansible-boxcar seal files/tls.box ./certs --mode '*.crt=0644' --force
ansible-playbook deploy-tls.yml
```

Hosts whose files already match report `ok`; the rest report `changed`. A
bundle is always rebuilt from source files; there is no "edit one entry in
place" command. Keep the plaintext sources somewhere appropriately protected
(a secrets manager, or an encrypted disk), not next to the bundle.

**Changing the password** works the same way: re-seal from the sources and
enter the new password. Redistribute the new password to operators through
your normal password manager.

### 5. Separate environments (dev, test, prod)

*Do:* one bundle and one password per environment, with its own sealed files:

```
files/dev.box     files/test.box     files/prod.box
```

```yaml
- sanjaynagpal.boxcar.unbox:
    src: "{{ env_name }}.box"
    dest: /etc/pki/app
    password: "{{ boxcar_password }}"
  no_log: true
```

A prod password cannot open a dev bundle and vice versa, and a leaked dev
password reveals nothing about prod.

### 6. Unattended runs (CI, cron, AWX)

The interactive prompt needs a person. For automation, supply the password
from the pipeline's own secret store instead, on the control node only:

```
BOXCAR_PASSWORD="$SECRET_FROM_CI" ansible-playbook deploy-tls.yml
```

and omit the `password:` line in the task (the module falls back to
`BOXCAR_PASSWORD`). Keep in mind that this moves the trust problem to your CI
secret store: anyone who can read that secret can open the bundle. Where
possible prefer the interactive prompt for production deployments.

If your playbook has a `vars_prompt` for `boxcar_password`, the prompt is
skipped automatically when that variable is already supplied with `-e`
(verified), so the same playbook serves both interactive and automated runs.
Otherwise omit `vars_prompt` and `password:` and rely on `BOXCAR_PASSWORD`.

### 6a. Avoid choosing or storing a password at all (SOPS)

*Situation:* nobody wants to invent a strong password or keep it in a CI
secret.

*Do:* generate the bundle password and keep it in a SOPS-encrypted file that
each operator and CI job opens with its own age key; the playbook reads it with
the `community.sops.sops` lookup and passes it to `unbox`. Adding or removing a
person is then a change to the recipient list, not a shared-password change.
Complete, tested walkthrough: [`examples/sops-combined`](../examples/sops-combined/README.md).

### 7. Recover or inspect sealed files locally (no Ansible)

*Situation:* the plaintext sources are gone, or you want to check what a
bundle really contains, or you need a certificate for a one-off manual task.

*Do:* unbox it with the same tool that sealed it:

```
tools/ansible-boxcar list files/tls.box                          # what is inside
tools/ansible-boxcar unbox files/tls.box ./recovered             # everything
tools/ansible-boxcar unbox files/tls.box ./recovered --entry server.crt
```

Files appear with the modes recorded in the bundle (private keys `0600`).
Treat the output folder as sensitive and delete it when finished. This is also
how you recover sources before re-sealing a bundle with a new password
(use case 4): unbox to a protected location, then `seal --force` with the new
password.

### 8. Verify a deployment without changing anything

```
ansible-playbook deploy-tls.yml --check
```

Check mode decrypts and validates the bundle and reports whether hosts would
change, without writing files.

## Command and module reference

### `tools/ansible-boxcar`

Built-in help: `ansible-boxcar --help` lists the commands with examples, and
`ansible-boxcar seal --help` (likewise `unbox`, `list`) gives the details,
options and examples of one command.

```
ansible-boxcar seal BUNDLE PATH [PATH ...] [--mode PATTERN=MODE ...] [--force]
ansible-boxcar unbox BUNDLE DEST [--entry NAME ...] [--force]
ansible-boxcar list BUNDLE
```

- `PATH` is a file (stored under its base name) or a folder (searched
  recursively; each file stored under its path relative to the folder).
- `--mode PATTERN=MODE` sets the permission bits for entries whose name matches
  the shell-style `PATTERN` (first match wins). Default `0600`.
- `--force` replaces an existing bundle; without it an existing file is never
  overwritten.
- Password: at least 8 characters, entered twice. A warning is shown below 16.
  `BOXCAR_PASSWORD` can supply it for non-interactive use.
- `unbox` decrypts the bundle into the local folder `DEST` (created with mode
  `0700` if missing), using the modes recorded in the bundle. The password is
  asked once. Nothing is written unless the password and **every** entry
  check out; `--entry NAME` (repeatable) restricts it to chosen entries; an
  existing file is never overwritten unless you pass `--force`, and that check
  happens before any file is written.
- Exit status `0` on success, `1` on error with a message on stderr.

### `sanjaynagpal.boxcar.unbox`

| Parameter | Required | Description |
|---|---|---|
| `src` | yes | Bundle path on the control node (searched in `files/` first). |
| `dest` | yes | Directory on the host; entries are created beneath it. |
| `password` | no | Bundle password. Falls back to `$BOXCAR_PASSWORD` on the control node. |
| `entries` | no | List of entry names to install. Default: all. |
| `owner`, `group` | no | Ownership of installed files and created directories. |
| `directory_mode` | no | Mode for created directories. Default `0700`. |

File modes come from the bundle, not from a module parameter, so they cannot
be altered by editing a playbook. The module returns an `entries` list (name,
destination, mode, changed). It never returns file content.

## Operating practices

- **Always set `no_log: true`** on the task. The module also avoids printing
  content itself, but `no_log` protects the password in tracebacks and verbose
  output.
- **Never use `--diff`** with this module; it refuses to run, because a diff
  would print decrypted content.
- **Choose a strong passphrase** (16+ characters). The bundle can be attacked
  offline by anyone who gets a copy; scrypt slows guessing but cannot save a
  weak password.
- **Keep the password out of the repo and out of the bundle's directory.** Use
  a password manager. Losing the password means re-sealing from the sources.
- **Keep the plaintext sources protected** and delete working copies when done.
- **Put `ANSIBLE_LOCAL_TEMP` on a tmpfs** (for example `/dev/shm/ansible`) so
  that the brief staging copy `copy` makes on the control node never reaches
  disk.
- **Limit who can read the control node's memory and temp directories**; the
  decrypted content is in the Ansible process while a play runs.

## Security notes and limits

What this protects against:

- Reading the bundle from disk, backups or Git without the password.
- Modification of the bundle: any change to a ciphertext, name or mode is
  detected before anything is written to a host.
- Loosening of file permissions by editing the bundle.

What it does not protect against:

- Anyone who has the password, or who can read the control node's memory or
  temp directories while a deployment runs.
- A compromised managed host after the files are installed. The installed
  files are ordinary files with the modes you set.
- A weak password. Nothing is stored that could confirm a guess, but an
  attacker with a copy of the bundle can try guesses offline.

Current limits:

- **Text entries only** (PEM and similar). Binary files such as `.p12` or
  `.jks` are rejected with a clear error.
- The bundle password is derived once per host per play (about 0.1 second).
- There is no in-place edit or password-change command; unbox (or use your
  sources) and re-seal.
- The bundle format is independent of the Go `boxcar` tool and is not
  interchangeable with its vault files.
- Tested against ansible-core 2.16 on localhost; run it against a non-production
  host first.

## Troubleshooting

| Message | Cause and fix |
|---|---|
| `incorrect password or corrupted bundle` | Wrong password, or the bundle was modified or damaged. Check for a typo and for a stale copy of the bundle. |
| `no password: set the 'password' parameter ... or $BOXCAR_PASSWORD` | Neither was provided. Add `password:` or set the variable on the control node. |
| `refuses to run with --diff` | Remove `--diff` from the command line. |
| `not in bundle: NAME` | An `entries` name is misspelled. Check with `ansible-boxcar list`. |
| `only supports text entries (PEM etc.)` | An entry is binary. Convert to PEM, or deliver it another way. |
| `unsupported parameter(s): ...` | A task option is misspelled. See the parameter table above. |
| `Could not find or access 'tls.box'` | The bundle is not in `files/` beside the playbook. Put it there or give a path. |
| `<name> already exists (use --force ...)` | `seal` and `unbox` never overwrite silently. Add `--force` if replacing is intended. |
| `The module sanjaynagpal.boxcar.unbox was not found` | The collection is not on `collections_path`. See Quick start step 1. |

**The task fails and the reason is hidden.** `no_log: true` hides errors too.
Temporarily remove it, and use a throwaway test password, to see the message.

**Passing the password with `-e`.** Do not write `-e "pw=correct horse"`;
Ansible splits `key=value` on spaces and the password is truncated. Use JSON
(`-e '{"pw": "correct horse"}'`) or a vars file (`-e @vars.json`), and remember
that command-line arguments are visible to other users in the process list.
The interactive `vars_prompt` avoids that.

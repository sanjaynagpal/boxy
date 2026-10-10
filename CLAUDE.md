# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`boxy` is a Python/Ansible tool for protecting keys, certificates and PEM files at rest with an operator-supplied password, then installing them on managed hosts. It is an independent implementation inspired by the Go `boxcar` tool; the format is **not** compatible with it. Targets ansible-core 2.16 / Python 3.12; the only third-party dependency is `cryptography`. See `README.md` and `docs/USER-GUIDE.md` for user-facing docs.

## Commands

```
pip install cryptography
python -m unittest discover -s tests -v                 # unit tests (pure Python, run anywhere)
python -m unittest tests.test_bundle.RoundTrip -v       # one class (append .test_name for one test)
```

Integration tests need a real ansible-core on a Linux filesystem (file modes are asserted, so not `/mnt/c`; use WSL/Ubuntu):

```
tests/integration/setup-wsl.sh        # once: Python 3.12 + ansible-core via uv, no sudo
tests/integration/run.sh              # unbox plugin against localhost
tests/integration/setup-sops-wsl.sh   # once: sops, age, community.sops
tests/integration/sops.sh             # examples/sops-combined end-to-end
```

Override the venv/tool locations with `BOXY_VENV` (default `~/bx-ansible`) and `BOXY_TOOLS` (default `~/bx-tools`). The scripts copy the repo to a temp dir, so the checkout is never modified.

CLI: `tools/ansible-boxcar {seal,unbox,list} ...` (`--help` on each). `$BOXCAR_PASSWORD` supplies the password non-interactively for testing only.

## Architecture

Three pieces share one crypto core:

- `collections/ansible_collections/sanjaynagpal/boxcar/plugins/module_utils/bundle.py` — the bundle format and all crypto (seal / open / list). One scrypt-derived AES-256 key per bundle; each entry is AES-256-GCM with its own nonce. The AEAD additional data binds ciphertext to bundle id + entry name + file mode, so entries can't be renamed, moved or have modes loosened. No password hash is stored (wrong password = GCM failure). `open_bundle` authenticates **every** entry before returning anything so callers never write partial output. Reader enforces upper bounds on scrypt params to resist hostile files. Raises `BundleError` for all invalid input.
- `plugins/action/unbox.py` — the `sanjaynagpal.boxcar.unbox` **action plugin**. Decryption runs on the control node; writing is delegated to `ansible.builtin.copy` once per entry (atomic, idempotent, ownership handled by Ansible). Refuses `--diff`; whitelist of args in `_VALID_ARGS`.
- `plugins/modules/unbox.py` — module stub that exists for documentation/argument spec only; the real logic is the action plugin.
- `tools/ansible-boxcar` — standalone CLI (no `.py` extension) for the operator workstation. It imports `bundle.py` by inserting the collection's `module_utils` dir into `sys.path`, so the same file is imported as a plain module by the CLI and tests, and as `ansible_collections.…module_utils.bundle` by the plugin. Keep `bundle.py` free of Ansible imports and depend only on `cryptography` + stdlib.

`tests/test_bundle.py` imports `bundle` the same `sys.path` way. `examples/sops-combined/` shows keeping the bundle password in a SOPS/age file instead of typing it.

## Conventions worth knowing

- Text entries only (PEM etc.); binary entries are rejected. Entry names are validated as safe relative slash-separated paths (`validate_name`).
- Default entry mode is 0600; the CLI's `--mode PATTERN=MODE` uses fnmatch, first match wins.
- Plugin usage must set `no_log: true`; never log decrypted content.
- Work happens on feature branches merged via PRs (`feature/...`).

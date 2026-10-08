# boxy
Python based boxcar that can be used in ansible

Protects keys, certificates and PEM files at rest on the Ansible control node
with an operator-supplied password, and installs them on managed hosts.
Inspired by the Go `boxcar` tool but an independent, Ansible-native
implementation (format is **not** compatible).

Targets ansible-core 2.16, Python 3.12. The control node needs the
`cryptography` package (already an ansible-core dependency).

## Seal (operator workstation / control node)

```
tools/ansible-boxcar seal tls.box ./certs --mode '*.crt=0644'   # prompts for password twice
tools/ansible-boxcar list tls.box                               # names + modes, no password
```

A folder is stored with paths relative to it; default mode is 0600.
`tls.box` is safe to keep at rest and to commit.

## Unbox (playbook)

Make the collection findable (`collections_path = ./collections` in
`ansible.cfg`), then:

```yaml
- hosts: webservers
  vars_prompt:
    - name: boxcar_password
      prompt: Bundle password
      private: true
  tasks:
    - name: Install TLS material
      sanjaynagpal.boxcar.unbox:
        src: tls.box
        dest: /etc/pki/app
        password: "{{ boxcar_password }}"
        owner: root
        group: ssl-cert
      no_log: true
```

Decryption happens on the control node; every entry is authenticated before
anything is written, so a wrong password changes nothing. Writing is
delegated to `ansible.builtin.copy`, so it is atomic and idempotent.

## Limits / caveats

- Text entries only (PEM etc.); binary entries are rejected.
- Plaintext briefly passes through the controller's local temp dir
  (`ANSIBLE_LOCAL_TEMP`, used by `copy`) and the remote temp dir; point the
  former at a tmpfs.
- Refuses `--diff`. Always set `no_log: true`.
- scrypt runs once per host (~0.1 s); there is no cross-host cache.

## Tests

```
pip install cryptography
python -m unittest discover -s tests -v
```

End-to-end tests against a real ansible-core 2.16 (Python 3.12), on a Linux
filesystem such as WSL/Ubuntu (file modes are asserted):

```
tests/integration/setup-wsl.sh   # once: Python 3.12 + ansible-core via uv, no sudo
tests/integration/run.sh         # runs the unbox plugin against localhost
```

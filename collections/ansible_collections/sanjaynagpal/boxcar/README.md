# sanjaynagpal.boxcar

Protect keys, certificates and PEM files at rest on the Ansible control node
with an operator-supplied password, and install them on managed hosts.

- `tools/ansible-boxcar seal` (repo root) encrypts files/folders into one bundle.
- `sanjaynagpal.boxcar.unbox` decrypts on the control node and installs the files.

See the repository README for usage.

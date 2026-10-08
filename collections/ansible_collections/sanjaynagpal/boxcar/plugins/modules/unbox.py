#!/usr/bin/python
# This file only carries the documentation; the work is done by the action
# plugin of the same name (plugins/action/unbox.py), which runs on the
# control node.
from __future__ import annotations

DOCUMENTATION = r"""
---
module: unbox
short_description: Decrypt a sealed bundle on the controller and install its files
version_added: "0.1.0"
description:
  - Decrypts a bundle created by C(tools/ansible-boxcar seal) on the control node,
    using a password supplied by the operator, and writes the contained files
    to the managed host through M(ansible.builtin.copy).
  - Every entry is authenticated before anything is written, so a wrong
    password or a tampered bundle changes nothing on the host.
  - Only text entries (PEM keys and certificates and the like) are supported.
  - Plaintext briefly exists in the controller's local temp directory (see
    C(ANSIBLE_LOCAL_TEMP)) while M(ansible.builtin.copy) stages it; point that
    at a tmpfs for stronger guarantees.
  - Always set C(no_log: true) on the task. Refuses to run with C(--diff).
options:
  src:
    description: Path to the bundle on the control node (searched like C(files/) for roles).
    type: path
    required: true
  dest:
    description: Directory on the managed host; entry names are created beneath it.
    type: path
    required: true
  password:
    description:
      - Bundle password. Normally set from C(vars_prompt) with C(private: true).
      - Falls back to the C(BOXCAR_PASSWORD) environment variable on the control node.
    type: str
  entries:
    description: Names of the entries to install. Default is every entry.
    type: list
    elements: str
  owner:
    description: Owner of installed files and created directories.
    type: str
  group:
    description: Group of installed files and created directories.
    type: str
  directory_mode:
    description: Mode of created directories.
    type: str
    default: "0700"
notes:
  - File modes come from the bundle (set at seal time) and are authenticated.
author:
  - Sanjay Nagpal
"""

EXAMPLES = r"""
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
"""

RETURN = r"""
entries:
  description: One item per installed entry (never includes content).
  returned: success
  type: list
  elements: dict
  contains:
    name: {description: Entry name in the bundle., type: str}
    dest: {description: Path written on the host., type: str}
    mode: {description: Mode applied., type: str}
    changed: {description: Whether this file was created or modified., type: bool}
"""

from ansible.module_utils.basic import AnsibleModule


def main():
    AnsibleModule(argument_spec={}, supports_check_mode=True).fail_json(
        msg="sanjaynagpal.boxcar.unbox is implemented as an action plugin and must run via Ansible")


if __name__ == "__main__":
    main()

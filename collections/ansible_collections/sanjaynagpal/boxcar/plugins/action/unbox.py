from __future__ import annotations

import os
import posixpath

from ansible.errors import AnsibleActionFail, AnsibleError
from ansible.plugins.action import ActionBase
from ansible_collections.sanjaynagpal.boxcar.plugins.module_utils import bundle

_VALID_ARGS = frozenset(("src", "dest", "password", "entries", "owner", "group", "directory_mode"))


class ActionModule(ActionBase):
    """Decrypt a sealed bundle on the control node and place its files on the host.

    Decryption happens here, on the controller; the actual writing is
    delegated to ansible.builtin.copy (one call per entry), so atomic
    replacement, ownership and checksum-based idempotency are Ansible's own.
    """

    TRANSFERS_FILES = True

    def run(self, tmp=None, task_vars=None):
        result = super().run(tmp, task_vars)
        del tmp
        task_vars = task_vars or {}
        args = self._task.args

        unknown = sorted(set(args) - _VALID_ARGS)
        if unknown:
            raise AnsibleActionFail("unsupported parameter(s): %s" % ", ".join(unknown))
        for required in ("src", "dest"):
            if not args.get(required):
                raise AnsibleActionFail("missing required parameter: %s" % required)
        if self._task.diff or self._play_context.diff:
            raise AnsibleActionFail("sanjaynagpal.boxcar.unbox refuses to run with --diff: "
                                    "it would print decrypted content")

        password = args.get("password")
        if not password:
            password = os.environ.get("BOXCAR_PASSWORD")
        if not password:
            raise AnsibleActionFail("no password: set the 'password' parameter (e.g. from "
                                    "vars_prompt) or $BOXCAR_PASSWORD on the control node")
        password = str(password).encode("utf-8")

        try:
            src = self._find_needle("files", str(args["src"]))
        except AnsibleError as exc:
            raise AnsibleActionFail(str(exc)) from None

        try:
            entries = bundle.open_bundle(bundle.load(src), password)
        except bundle.BundleError as exc:
            raise AnsibleActionFail(str(exc)) from None

        wanted = args.get("entries")
        if wanted is not None:
            if isinstance(wanted, str):
                wanted = [wanted]
            missing = sorted(set(wanted) - {e.name for e in entries})
            if missing:
                raise AnsibleActionFail("not in bundle: %s" % ", ".join(missing))
            entries = [e for e in entries if e.name in set(wanted)]

        try:
            texts = {e.name: e.data.decode("utf-8") for e in entries}
        except UnicodeDecodeError as exc:
            raise AnsibleActionFail("this version only supports text entries (PEM etc.); "
                                    "an entry is not valid UTF-8: %s" % exc.reason) from None

        dest = str(args["dest"])
        ownership = {k: args[k] for k in ("owner", "group") if args.get(k)}
        dir_mode = str(args.get("directory_mode") or "0700")

        # ansible.builtin.copy does not create missing parent directories.
        dirs = {dest}
        for e in entries:
            parent = posixpath.dirname(posixpath.join(dest, e.name))
            while len(parent) > len(dest):
                dirs.add(parent)
                parent = posixpath.dirname(parent)
        for path in sorted(dirs, key=lambda p: (p.count("/"), p)):
            res = self._execute_module(
                module_name="ansible.legacy.file",
                module_args=dict(path=path, state="directory", mode=dir_mode, **ownership),
                task_vars=task_vars)
            if res.get("failed"):
                return {"failed": True, "msg": "cannot create directory %s: %s" % (path, res.get("msg"))}

        changed = False
        report = []
        for e in entries:
            target = posixpath.join(dest, e.name)
            res = self._run_copy(task_vars, dict(content=texts[e.name], dest=target,
                                                 mode="%04o" % e.mode, **ownership))
            if res.get("failed"):
                return {"failed": True, "msg": "cannot write %s: %s" % (target, res.get("msg"))}
            changed = changed or bool(res.get("changed"))
            report.append({"name": e.name, "dest": target, "mode": "%04o" % e.mode,
                           "changed": bool(res.get("changed"))})

        # Built from scratch on purpose: nothing from the copy results (content,
        # diff, invocation) may reach the callback output.
        result["changed"] = changed
        result["entries"] = report
        return result

    def _run_copy(self, task_vars, copy_args):
        new_task = self._task.copy()
        new_task.args = copy_args
        new_task.no_log = True
        copy_action = self._shared_loader_obj.action_loader.get(
            "ansible.legacy.copy",
            task=new_task,
            connection=self._connection,
            play_context=self._play_context,
            loader=self._loader,
            templar=self._templar,
            shared_loader_obj=self._shared_loader_obj)
        return copy_action.run(task_vars=task_vars)

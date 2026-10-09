import copy
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(
    ROOT, "collections", "ansible_collections", "sanjaynagpal", "boxcar", "plugins", "module_utils"))

import bundle  # noqa: E402

PW = b"correct horse battery"


def entries():
    return [
        bundle.Entry("server.key", 0o600, b"-----BEGIN PRIVATE KEY-----\nabc\n"),
        bundle.Entry("pki/server.crt", 0o644, b"-----BEGIN CERTIFICATE-----\ndef\n"),
    ]


class RoundTrip(unittest.TestCase):
    def test_round_trip_preserves_names_modes_data(self):
        out = bundle.open_bundle(bundle.seal(entries(), PW), PW)
        self.assertEqual(sorted(out, key=lambda e: e.name), sorted(entries(), key=lambda e: e.name))

    def test_wrong_password_fails(self):
        with self.assertRaises(bundle.BundleError):
            bundle.open_bundle(bundle.seal(entries(), PW), b"wrong password")

    def test_sealing_twice_differs(self):
        a, b = bundle.seal(entries(), PW), bundle.seal(entries(), PW)
        self.assertNotEqual(a["entries"][0]["ciphertext"], b["entries"][0]["ciphertext"])

    def test_list_needs_no_password(self):
        self.assertEqual(bundle.list_entries(bundle.seal(entries(), PW)),
                         [("pki/server.crt", 0o644), ("server.key", 0o600)])

    def test_plaintext_not_in_document(self):
        self.assertNotIn("PRIVATE KEY", str(bundle.seal(entries(), PW)))

    def test_save_load(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "x.box")
            doc = bundle.seal(entries(), PW)
            bundle.save(path, doc)
            self.assertEqual(bundle.load(path), doc)
            if os.name == "posix":
                self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)


class Tamper(unittest.TestCase):
    def setUp(self):
        self.doc = bundle.seal(entries(), PW)

    def assertRejected(self, doc):
        with self.assertRaises(bundle.BundleError):
            bundle.open_bundle(doc, PW)

    def test_changed_mode(self):
        doc = copy.deepcopy(self.doc)
        doc["entries"][1]["mode"] = "0644" if doc["entries"][1]["mode"] != "0644" else "0666"
        self.assertRejected(doc)

    def test_renamed_entry(self):
        doc = copy.deepcopy(self.doc)
        doc["entries"][0]["name"] = "other.key"
        self.assertRejected(doc)

    def test_swapped_ciphertext(self):
        doc = copy.deepcopy(self.doc)
        e0, e1 = doc["entries"]
        e0["ciphertext"], e1["ciphertext"] = e1["ciphertext"], e0["ciphertext"]
        self.assertRejected(doc)

    def test_entry_moved_to_other_bundle(self):
        other = bundle.seal(entries(), PW)
        doc = copy.deepcopy(self.doc)
        doc["entries"] = other["entries"]
        self.assertRejected(doc)

    def test_flipped_ciphertext_bit(self):
        doc = copy.deepcopy(self.doc)
        ct = bytearray(bundle._b64d(doc["entries"][0]["ciphertext"], "ct"))
        ct[0] ^= 1
        doc["entries"][0]["ciphertext"] = bundle._b64e(bytes(ct))
        self.assertRejected(doc)

    def test_hostile_scrypt_params(self):
        doc = copy.deepcopy(self.doc)
        doc["kdf"]["n"] = 1 << 30
        self.assertRejected(doc)


class Validation(unittest.TestCase):
    def test_unsafe_names(self):
        for bad in ("", "/etc/passwd", "../x", "a/../b", "a//b", "a\\b", "./x", "x\x00"):
            with self.assertRaises(bundle.BundleError, msg=bad):
                bundle.validate_name(bad)

    def test_unsafe_name_in_document_rejected(self):
        doc = bundle.seal(entries(), PW)
        doc["entries"][0]["name"] = "../escape"
        with self.assertRaises(bundle.BundleError):
            bundle.open_bundle(doc, PW)

    def test_modes(self):
        self.assertEqual(bundle.parse_mode("0600"), 0o600)
        for bad in ("0o999", "4755", "abc", -1, True, 0o1000):
            with self.assertRaises(bundle.BundleError, msg=repr(bad)):
                bundle.parse_mode(bad)

    def test_duplicate_and_file_dir_conflict(self):
        with self.assertRaises(bundle.BundleError):
            bundle.seal([bundle.Entry("a", 0o600, b"1"), bundle.Entry("a", 0o600, b"2")], PW)
        with self.assertRaises(bundle.BundleError):
            bundle.seal([bundle.Entry("a", 0o600, b"1"), bundle.Entry("a/b", 0o600, b"2")], PW)

    def test_short_password_and_empty_bundle(self):
        with self.assertRaises(bundle.BundleError):
            bundle.seal(entries(), b"short")
        with self.assertRaises(bundle.BundleError):
            bundle.seal([], PW)

    def test_not_a_bundle(self):
        for doc in (None, [], {}, {"format": "boxcar-ansible", "version": 99}):
            with self.assertRaises(bundle.BundleError):
                bundle.open_bundle(doc, PW)


class Cli(unittest.TestCase):
    def run_cli(self, *args, password=PW.decode()):
        env = dict(os.environ, BOXCAR_PASSWORD=password)
        return subprocess.run([sys.executable, os.path.join(ROOT, "tools", "ansible-boxcar"), *args],
                              capture_output=True, text=True, env=env)

    def test_seal_folder_and_list_with_modes(self):
        with tempfile.TemporaryDirectory() as d:
            src = os.path.join(d, "certs")
            os.makedirs(os.path.join(src, "sub"))
            for rel, body in (("a.pem", "A"), ("sub/b.key", "B")):
                with open(os.path.join(src, rel), "w") as fh:
                    fh.write(body)
            out = os.path.join(d, "x.box")
            r = self.run_cli("seal", out, src, "--mode", "*.pem=0644")
            self.assertEqual(r.returncode, 0, r.stderr)
            r = self.run_cli("list", out)
            self.assertEqual(r.stdout.splitlines(), ["0644  a.pem", "0600  sub/b.key"])
            got = bundle.open_bundle(bundle.load(out), PW.decode().encode())
            self.assertEqual({e.name: e.data for e in got}, {"a.pem": b"A", "sub/b.key": b"B"})

    def test_refuses_overwrite_without_force(self):
        with tempfile.TemporaryDirectory() as d:
            f, out = os.path.join(d, "f.pem"), os.path.join(d, "x.box")
            with open(f, "w") as fh:
                fh.write("x")
            self.assertEqual(self.run_cli("seal", out, f).returncode, 0)
            self.assertEqual(self.run_cli("seal", out, f).returncode, 1)
            self.assertEqual(self.run_cli("seal", out, f, "--force").returncode, 0)

    def test_help_for_every_command(self):
        r = self.run_cli()
        self.assertEqual(r.returncode, 2)  # no command: usage error, help shown
        self.assertIn("COMMAND", r.stderr)
        for cmd in ("seal", "unbox", "list"):
            self.assertIn(cmd, self.run_cli("--help").stdout)
            r = self.run_cli(cmd, "--help")
            self.assertEqual(r.returncode, 0, cmd)
            self.assertIn("usage: ansible-boxcar " + cmd, r.stdout)
        self.assertIn("--mode", self.run_cli("seal", "--help").stdout)
        self.assertIn("--entry", self.run_cli("unbox", "--help").stdout)
        self.assertIn("BOXCAR_PASSWORD", self.run_cli("--help").stdout)

    def run_cli_nopw(self, *args):
        env = {k: v for k, v in os.environ.items() if k != "BOXCAR_PASSWORD"}
        return subprocess.run([sys.executable, os.path.join(ROOT, "tools", "ansible-boxcar"), *args],
                              capture_output=True, text=True, env=env)

    def _one_file(self, d):
        f = os.path.join(d, "f.pem")
        with open(f, "w") as fh:
            fh.write("x")
        return f

    def test_generate_prints_only_the_password_on_stdout_and_it_opens_the_bundle(self):
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "x.box")
            r = self.run_cli_nopw("seal", out, self._one_file(d), "--generate")
            self.assertEqual(r.returncode, 0, r.stderr)
            pw = r.stdout.strip()
            self.assertEqual(len(r.stdout.splitlines()), 1)
            self.assertGreaterEqual(len(pw), 43)
            self.assertNotIn(pw, r.stderr)
            self.assertEqual(bundle.open_bundle(bundle.load(out), pw.encode())[0].data, b"x")

    def test_generate_passwords_differ(self):
        with tempfile.TemporaryDirectory() as d:
            f = self._one_file(d)
            a = self.run_cli_nopw("seal", os.path.join(d, "a.box"), f, "--generate").stdout
            b = self.run_cli_nopw("seal", os.path.join(d, "b.box"), f, "--generate").stdout
            self.assertNotEqual(a, b)

    def test_generate_password_file(self):
        with tempfile.TemporaryDirectory() as d:
            out, pwf = os.path.join(d, "x.box"), os.path.join(d, "x.pw")
            r = self.run_cli_nopw("seal", out, self._one_file(d), "--generate", "--password-file", pwf)
            self.assertEqual(r.returncode, 0, r.stderr)
            with open(pwf) as fh:
                pw = fh.read().strip()
            self.assertEqual(r.stdout, "")  # secret not printed
            self.assertNotIn(pw, r.stderr)
            if os.name == "posix":
                self.assertEqual(os.stat(pwf).st_mode & 0o777, 0o600)
            self.assertEqual(bundle.open_bundle(bundle.load(out), pw.encode())[0].data, b"x")

    def test_generate_refuses_clobbering_and_conflicts(self):
        with tempfile.TemporaryDirectory() as d:
            f, out, pwf = self._one_file(d), os.path.join(d, "x.box"), os.path.join(d, "x.pw")
            with open(pwf, "w") as fh:
                fh.write("precious")
            r = self.run_cli_nopw("seal", out, f, "--generate", "--password-file", pwf)
            self.assertEqual(r.returncode, 1)
            self.assertFalse(os.path.exists(out))  # nothing created
            with open(pwf) as fh:
                self.assertEqual(fh.read(), "precious")  # untouched
            self.assertEqual(self.run_cli_nopw("seal", out, f, "--generate", "--password-file", pwf,
                                               "--force").returncode, 0)
            self.assertEqual(self.run_cli_nopw("seal", os.path.join(d, "y.box"), f,
                                               "--password-file", pwf).returncode, 1)
            r = self.run_cli("seal", os.path.join(d, "z.box"), f, "--generate")  # env password set
            self.assertEqual(r.returncode, 1)
            self.assertIn("BOXCAR_PASSWORD", r.stderr)

    def _sealed(self, d):
        src = os.path.join(d, "certs")
        os.makedirs(os.path.join(src, "sub"))
        for rel, body in (("a.pem", "A"), ("sub/b.key", "B")):
            with open(os.path.join(src, rel), "w") as fh:
                fh.write(body)
        out = os.path.join(d, "x.box")
        self.assertEqual(self.run_cli("seal", out, src, "--mode", "*.pem=0644").returncode, 0)
        return out

    def test_unbox_round_trip(self):
        with tempfile.TemporaryDirectory() as d:
            out, dest = self._sealed(d), os.path.join(d, "dest")
            r = self.run_cli("unbox", out, dest)
            self.assertEqual(r.returncode, 0, r.stderr)
            with open(os.path.join(dest, "a.pem")) as fh:
                self.assertEqual(fh.read(), "A")
            with open(os.path.join(dest, "sub", "b.key")) as fh:
                self.assertEqual(fh.read(), "B")
            if os.name == "posix":
                self.assertEqual(os.stat(os.path.join(dest, "a.pem")).st_mode & 0o777, 0o644)
                self.assertEqual(os.stat(os.path.join(dest, "sub", "b.key")).st_mode & 0o777, 0o600)

    def test_unbox_wrong_password_writes_nothing(self):
        with tempfile.TemporaryDirectory() as d:
            out, dest = self._sealed(d), os.path.join(d, "dest")
            r = self.run_cli("unbox", out, dest, password="not the password")
            self.assertEqual(r.returncode, 1)
            self.assertFalse(os.path.exists(dest))

    def test_unbox_refuses_overwrite_without_writing_anything(self):
        with tempfile.TemporaryDirectory() as d:
            out, dest = self._sealed(d), os.path.join(d, "dest")
            os.makedirs(os.path.join(dest, "sub"))
            with open(os.path.join(dest, "sub", "b.key"), "w") as fh:
                fh.write("existing")
            r = self.run_cli("unbox", out, dest)
            self.assertEqual(r.returncode, 1)
            self.assertFalse(os.path.exists(os.path.join(dest, "a.pem")))  # nothing half-written
            with open(os.path.join(dest, "sub", "b.key")) as fh:
                self.assertEqual(fh.read(), "existing")
            self.assertEqual(self.run_cli("unbox", out, dest, "--force").returncode, 0)
            with open(os.path.join(dest, "sub", "b.key")) as fh:
                self.assertEqual(fh.read(), "B")

    def test_unbox_entry_filter(self):
        with tempfile.TemporaryDirectory() as d:
            out, dest = self._sealed(d), os.path.join(d, "dest")
            self.assertEqual(self.run_cli("unbox", out, dest, "--entry", "a.pem").returncode, 0)
            self.assertTrue(os.path.exists(os.path.join(dest, "a.pem")))
            self.assertFalse(os.path.exists(os.path.join(dest, "sub")))
            r = self.run_cli("unbox", out, os.path.join(d, "d2"), "--entry", "nope")
            self.assertEqual(r.returncode, 1)
            self.assertIn("not in bundle", r.stderr)


if __name__ == "__main__":
    unittest.main()

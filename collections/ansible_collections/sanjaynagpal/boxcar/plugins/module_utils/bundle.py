"""Sealed-bundle format for the sanjaynagpal.boxcar collection.

A bundle is a JSON document holding any number of named, encrypted files
(keys, certificates, PEM files) that share one password. It is inspired by
the Go ``boxcar`` tool but is an independent format and is not compatible
with it.

Design, in brief:

* One password -> one AES-256 key, derived with scrypt over a per-bundle
  random salt. Deriving once per bundle (not once per entry) keeps unboxing
  a folder of artifacts cheap.
* Every entry is sealed with AES-256-GCM under a fresh random 96-bit nonce.
* The AEAD additional data binds each ciphertext to the bundle id, the entry
  name and the entry's file mode. An entry therefore cannot be renamed,
  moved to another bundle, or have its mode loosened without detection.
* There is no stored password hash: a wrong password simply fails GCM
  authentication.
* ``open_bundle`` decrypts and authenticates *every* entry before returning
  anything, so a caller never writes a partial result.

Only ``cryptography`` and the standard library are used, so this module can
be imported by Ansible plugins and by the standalone sealing script alike.
"""
from __future__ import annotations

import base64
import binascii
import json
import os
import secrets
import tempfile
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

FORMAT = "boxcar-ansible"
VERSION = 1

# scrypt cost used for newly sealed bundles (interactive-login strength).
SCRYPT_N = 1 << 15
SCRYPT_R = 8
SCRYPT_P = 1

# Upper bounds accepted when *reading* a bundle, so a hostile or corrupt
# file cannot make the control node allocate unbounded memory.
_MAX_N = 1 << 20
_MAX_R = 32
_MAX_P = 16

KEY_LEN = 32
SALT_LEN = 16
ID_LEN = 16
NONCE_LEN = 12

MIN_PASSWORD_LEN = 8
RECOMMENDED_PASSWORD_LEN = 16
DEFAULT_MODE = 0o600

_AAD_PREFIX = b"boxcar-ansible/v1\x00"


class BundleError(Exception):
    """Raised for any invalid input, malformed bundle or failed decryption."""


@dataclass(frozen=True)
class Entry:
    name: str  # slash-separated relative path, e.g. "pki/server.key"
    mode: int  # permission bits, e.g. 0o600
    data: bytes


def validate_name(name: str) -> str:
    """Return name if it is a safe, relative, slash-separated path."""
    if not isinstance(name, str) or not name or len(name) > 1024:
        raise BundleError("invalid entry name %r" % (name,))
    if "\x00" in name or "\\" in name or name.startswith("/"):
        raise BundleError("unsafe entry name %r" % (name,))
    for part in name.split("/"):
        if part in ("", ".", ".."):
            raise BundleError("unsafe entry name %r" % (name,))
    return name


def parse_mode(value) -> int:
    """Accept 0o600, 384, or an octal string such as "0600"; return an int."""
    if isinstance(value, str):
        try:
            value = int(value, 8)
        except ValueError:
            raise BundleError("invalid file mode %r" % (value,)) from None
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= 0o777:
        raise BundleError("invalid file mode %r (allowed: 0000-0777)" % (value,))
    return value


def check_password(password: bytes) -> None:
    if len(password) < MIN_PASSWORD_LEN:
        raise BundleError("password must be at least %d characters" % MIN_PASSWORD_LEN)


def generate_password() -> str:
    """Return a random URL-safe password with 256 bits of entropy (43 characters)."""
    return secrets.token_urlsafe(32)


def is_weak_password(password: bytes) -> bool:
    """Advisory only: True if shorter than RECOMMENDED_PASSWORD_LEN."""
    return len(password) < RECOMMENDED_PASSWORD_LEN


def _b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _b64d(value, what: str, length: int | None = None) -> bytes:
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError, TypeError):
        raise BundleError("bundle field %s is not valid base64" % what) from None
    if length is not None and len(raw) != length:
        raise BundleError("bundle field %s has the wrong length" % what)
    return raw


def _derive_key(password: bytes, salt: bytes, n: int, r: int, p: int) -> bytes:
    return Scrypt(salt=salt, length=KEY_LEN, n=n, r=r, p=p).derive(password)


def _aad(bundle_id: bytes, name: str, mode: int) -> bytes:
    return _AAD_PREFIX + bundle_id + b"\x00" + name.encode("utf-8") + b"\x00" + b"%04o" % mode


def _check_no_path_conflicts(names) -> None:
    """Reject duplicate names, and a name that is also a directory of another."""
    seen = set()
    for name in names:
        if name in seen:
            raise BundleError("duplicate entry name %r" % name)
        seen.add(name)
    for name in seen:
        parts = name.split("/")
        for i in range(1, len(parts)):
            if "/".join(parts[:i]) in seen:
                raise BundleError("entry %r conflicts with entry %r (file vs. directory)"
                                  % (name, "/".join(parts[:i])))


def seal(entries, password: bytes) -> dict:
    """Encrypt entries (an iterable of Entry) into a new bundle document."""
    check_password(password)
    entries = sorted(entries, key=lambda e: e.name)
    if not entries:
        raise BundleError("a bundle needs at least one entry")
    for e in entries:
        validate_name(e.name)
        parse_mode(e.mode)
    _check_no_path_conflicts([e.name for e in entries])

    bundle_id = secrets.token_bytes(ID_LEN)
    salt = secrets.token_bytes(SALT_LEN)
    aead = AESGCM(_derive_key(password, salt, SCRYPT_N, SCRYPT_R, SCRYPT_P))
    sealed = []
    for e in entries:
        nonce = secrets.token_bytes(NONCE_LEN)
        ct = aead.encrypt(nonce, e.data, _aad(bundle_id, e.name, e.mode))
        sealed.append({
            "name": e.name,
            "mode": "%04o" % e.mode,
            "nonce": _b64e(nonce),
            "ciphertext": _b64e(ct),
        })
    return {
        "format": FORMAT,
        "version": VERSION,
        "id": _b64e(bundle_id),
        "kdf": {"name": "scrypt", "n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P, "salt": _b64e(salt)},
        "entries": sealed,
    }


def _parse(doc) -> tuple:
    """Validate the document's structure; return (id, kdf params, raw entries)."""
    if not isinstance(doc, dict) or doc.get("format") != FORMAT:
        raise BundleError("not a boxcar-ansible bundle")
    if doc.get("version") != VERSION:
        raise BundleError("unsupported bundle version %r" % (doc.get("version"),))
    bundle_id = _b64d(doc.get("id"), "id", ID_LEN)

    kdf = doc.get("kdf")
    if not isinstance(kdf, dict) or kdf.get("name") != "scrypt":
        raise BundleError("unsupported key derivation function")
    n, r, p = kdf.get("n"), kdf.get("r"), kdf.get("p")
    for v in (n, r, p):
        if not isinstance(v, int) or isinstance(v, bool) or v < 1:
            raise BundleError("invalid scrypt parameters")
    if n & (n - 1) or n < 2 or n > _MAX_N or r > _MAX_R or p > _MAX_P:
        raise BundleError("scrypt parameters are out of the accepted range")
    salt = _b64d(kdf.get("salt"), "kdf.salt", SALT_LEN)

    raw = doc.get("entries")
    if not isinstance(raw, list) or not raw:
        raise BundleError("bundle has no entries")
    for item in raw:
        if not isinstance(item, dict):
            raise BundleError("malformed entry in bundle")
        validate_name(item.get("name"))
        parse_mode(item.get("mode"))
    _check_no_path_conflicts([item["name"] for item in raw])
    return bundle_id, (salt, n, r, p), raw


def list_entries(doc) -> list:
    """Return [(name, mode)] without needing the password."""
    _, _, raw = _parse(doc)
    return [(item["name"], parse_mode(item["mode"])) for item in raw]


def open_bundle(doc, password: bytes) -> list:
    """Decrypt every entry; raise BundleError (and return nothing) on any failure."""
    bundle_id, (salt, n, r, p), raw = _parse(doc)
    aead = AESGCM(_derive_key(password, salt, n, r, p))
    out = []
    for item in raw:
        mode = parse_mode(item["mode"])
        nonce = _b64d(item.get("nonce"), "nonce", NONCE_LEN)
        ct = _b64d(item.get("ciphertext"), "ciphertext")
        try:
            data = aead.decrypt(nonce, ct, _aad(bundle_id, item["name"], mode))
        except InvalidTag:
            raise BundleError("incorrect password or corrupted bundle") from None
        out.append(Entry(item["name"], mode, data))
    return out


def load(path: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except OSError as exc:
        raise BundleError("cannot read bundle %s: %s" % (path, exc.strerror or exc)) from None
    except ValueError:
        raise BundleError("%s is not a valid bundle (bad JSON)" % path) from None


def save(path: str, doc: dict) -> None:
    """Write doc to path (mode 0600) via a temp file in the same directory."""
    directory = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(prefix=".boxcar-", suffix=".tmp", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, indent=2)
            fh.write("\n")
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise

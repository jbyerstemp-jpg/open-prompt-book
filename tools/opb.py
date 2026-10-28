#!/usr/bin/env python3
"""opb - signing and verification tool for The Open Prompt Book.

Every action in the book (submitting an entry, testing it, reviewing it,
voting on it, delegating to an agent) is a small signed statement stored as
a file in ledger/events/. This tool creates those statements and replays all
of them to compute, deterministically, what the book's current state is.

Formats (see TRUST.md for the full specification):
  * Statements are in-toto v1 Statements, encoded as canonical JSON
    (RFC 8785 subset: no floats, ASCII object keys).
  * Statements are wrapped in DSSE envelopes.
  * Signatures are OpenSSH "SSHSIG" signatures with Ed25519 keys, so people
    can sign with the SSH key they already use for GitHub, and anyone can
    cross-check a signature with `ssh-keygen -Y verify` (see export-ssh).
  * The order of events is an append-only log (ledger/log.txt) committed to
    by signed Merkle checkpoints (RFC 6962 tree hashing).

A valid signature proves WHO signed WHAT. It never proves that a prompt is
safe or useful; that is what tests, reviews and votes are for.

Requires Python 3.9+ and the `cryptography` package.
"""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import getpass
import hashlib
import json
import os
import re
import struct
import sys
from pathlib import Path

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
except ImportError:  # pragma: no cover
    sys.exit("opb needs the 'cryptography' package. Install it with: pip install cryptography")

TOOL_VERSION = "0.1.0"
PAYLOAD_TYPE = "application/vnd.in-toto+json"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_PREFIX = "urn:openpromptbook:predicate:"
REGISTRY_FILES = ("governance/members.json", "governance/policy.json", "schemas/predicates.json")
REGISTRY_SIG = "governance/registry.sig.json"
EVENTS_DIR = "ledger/events"
LOG_FILE = "ledger/log.txt"
CHECKPOINT_DIR = "ledger/checkpoints"
ENTRIES_DIR = "entries"
LEDGER_ONLY_TYPES = {"registry", "checkpoint"}  # never stored in ledger/events

ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,38}$")
TIME_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")

SAFETY_NOTE = ("Signatures prove who signed what. They do not prove that a prompt is "
               "safe or useful, and nothing in this book grants any permission to act.")


class OPBError(Exception):
    """A problem with input data. The message is safe to show to users."""


# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(text: str) -> bytes:
    """Strict standard base64: one valid spelling per byte string."""
    if not isinstance(text, str):
        raise OPBError("expected a base64 string")
    try:
        data = base64.b64decode(text, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise OPBError(f"invalid base64: {exc}") from None
    if b64e(data) != text:
        raise OPBError("non-canonical base64")
    return data


def now_utc(override: str | None = None) -> dt.datetime:
    if override:
        return parse_time(override)
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0)


def parse_time(text: str) -> dt.datetime:
    if not isinstance(text, str) or not TIME_RE.match(text):
        raise OPBError(f"time must look like 2026-01-31T12:00:00Z, got {text!r}")
    try:
        return dt.datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)
    except ValueError:
        raise OPBError(f"invalid time {text!r}") from None


def fmt_time(value: dt.datetime) -> str:
    return value.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------------------
# Canonical JSON (the RFC 8785 subset we allow: no floats, ASCII keys)
# --------------------------------------------------------------------------

def _check_canonical_value(value, path: str = "$") -> None:
    if value is None or isinstance(value, (bool, str)):
        if isinstance(value, str):
            try:
                value.encode("utf-8")
            except UnicodeEncodeError:
                raise OPBError(f"{path}: invalid Unicode") from None
        return
    if isinstance(value, int):
        if abs(value) > 2**53 - 1:
            raise OPBError(f"{path}: integer out of range")
        return
    if isinstance(value, float):
        raise OPBError(f"{path}: floating-point numbers are not allowed")
    if isinstance(value, list):
        for i, item in enumerate(value):
            _check_canonical_value(item, f"{path}[{i}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str) or not key.isascii():
                raise OPBError(f"{path}: object keys must be ASCII strings")
            _check_canonical_value(item, f"{path}.{key}")
        return
    raise OPBError(f"{path}: unsupported value type {type(value).__name__}")


def canonical(value) -> bytes:
    _check_canonical_value(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _reject_duplicates(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise OPBError(f"duplicate JSON key {key!r}")
        out[key] = value
    return out


def _reject_float(text):
    raise OPBError("floating-point numbers are not allowed")


def _reject_constant(text):
    raise OPBError(f"{text} is not allowed in JSON")


def parse_json(data: bytes):
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise OPBError("file is not valid UTF-8") from None
    try:
        return json.loads(text, object_pairs_hook=_reject_duplicates,
                          parse_float=_reject_float, parse_constant=_reject_constant)
    except json.JSONDecodeError as exc:
        raise OPBError(f"invalid JSON: {exc}") from None


def read_json(path: Path):
    try:
        return parse_json(path.read_bytes())
    except FileNotFoundError:
        raise OPBError(f"missing file: {path}") from None


def write_json(path: Path, value) -> None:
    _check_canonical_value(value)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")


# --------------------------------------------------------------------------
# OpenSSH keys and SSHSIG signatures (Ed25519 only)
# --------------------------------------------------------------------------

def _ssh_string(data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + data


class _Reader:
    def __init__(self, data: bytes):
        self.data, self.pos = data, 0

    def take(self, n: int) -> bytes:
        if n < 0 or self.pos + n > len(self.data):
            raise OPBError("truncated SSH data")
        out = self.data[self.pos:self.pos + n]
        self.pos += n
        return out

    def u32(self) -> int:
        return struct.unpack(">I", self.take(4))[0]

    def string(self) -> bytes:
        return self.take(self.u32())

    def finish(self) -> None:
        if self.pos != len(self.data):
            raise OPBError("unexpected trailing bytes in SSH data")


class PublicKey:
    def __init__(self, raw: bytes):
        if len(raw) != 32:
            raise OPBError("Ed25519 public keys are 32 bytes")
        self.raw = raw
        self.wire = _ssh_string(b"ssh-ed25519") + _ssh_string(raw)

    @classmethod
    def from_wire(cls, blob: bytes) -> "PublicKey":
        reader = _Reader(blob)
        alg = reader.string()
        raw = reader.string()
        reader.finish()
        if alg != b"ssh-ed25519":
            raise OPBError("only ssh-ed25519 keys are supported (create one with: ssh-keygen -t ed25519)")
        return cls(raw)

    @classmethod
    def from_line(cls, line: str) -> "PublicKey":
        parts = (line or "").strip().split()
        if len(parts) < 2 or parts[0] != "ssh-ed25519":
            raise OPBError("public key must be an 'ssh-ed25519 AAAA...' line")
        return cls.from_wire(b64d(parts[1]))

    @property
    def fingerprint(self) -> str:
        """Same format as `ssh-keygen -l`: SHA256:<unpadded base64>."""
        return "SHA256:" + b64e(hashlib.sha256(self.wire).digest()).rstrip("=")

    @property
    def wire_sha256(self) -> str:
        return sha256_hex(self.wire)

    def line(self, comment: str = "") -> str:
        return ("ssh-ed25519 " + b64e(self.wire) + (" " + comment if comment else "")).strip()

    def verify_raw(self, signature: bytes, data: bytes) -> None:
        try:
            Ed25519PublicKey.from_public_bytes(self.raw).verify(signature, data)
        except InvalidSignature:
            raise OPBError("signature does not verify") from None


def public_of(private: Ed25519PrivateKey) -> PublicKey:
    return PublicKey(private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw))


def load_private_key(path: str) -> Ed25519PrivateKey:
    data = Path(path).expanduser().read_bytes()
    password = os.environ.get("OPB_KEY_PASSPHRASE")
    try:
        key = serialization.load_ssh_private_key(data, password=password.encode() if password else None)
    except TypeError:
        if password is None and sys.stdin.isatty():
            entered = getpass.getpass(f"Passphrase for {path}: ")
            key = serialization.load_ssh_private_key(data, password=entered.encode())
        else:
            raise OPBError("this key is passphrase-protected: set OPB_KEY_PASSPHRASE or run interactively") from None
    except ValueError as exc:
        raise OPBError(f"could not read private key {path}: {exc}") from None
    if not isinstance(key, Ed25519PrivateKey):
        raise OPBError("only Ed25519 keys are supported (create one with: ssh-keygen -t ed25519)")
    return key


def load_public_key_file(path: str) -> PublicKey:
    return PublicKey.from_line(Path(path).expanduser().read_text(encoding="utf-8"))


def _sshsig_signed_data(namespace: bytes, hash_alg: bytes, message: bytes, reserved: bytes = b"") -> bytes:
    digest = hashlib.new(hash_alg.decode(), message).digest()
    return (b"SSHSIG" + _ssh_string(namespace) + _ssh_string(reserved)
            + _ssh_string(hash_alg) + _ssh_string(digest))


def sshsig_sign(private: Ed25519PrivateKey, message: bytes, namespace: str) -> bytes:
    """Produce an OpenSSH SSHSIG blob (PROTOCOL.sshsig), hash sha512, like ssh-keygen -Y sign."""
    ns = namespace.encode()
    signature = private.sign(_sshsig_signed_data(ns, b"sha512", message))
    sig_wire = _ssh_string(b"ssh-ed25519") + _ssh_string(signature)
    return (b"SSHSIG" + struct.pack(">I", 1) + _ssh_string(public_of(private).wire)
            + _ssh_string(ns) + _ssh_string(b"") + _ssh_string(b"sha512") + _ssh_string(sig_wire))


def sshsig_verify(blob: bytes, message: bytes, namespace: str) -> PublicKey:
    """Verify an SSHSIG blob and return the key that made it."""
    reader = _Reader(blob)
    if reader.take(6) != b"SSHSIG":
        raise OPBError("not an SSH signature")
    if reader.u32() != 1:
        raise OPBError("unsupported SSH signature version")
    key = PublicKey.from_wire(reader.string())
    ns = reader.string()
    reserved = reader.string()
    hash_alg = reader.string()
    sig_wire = reader.string()
    reader.finish()
    if ns != namespace.encode():
        raise OPBError("signature was made for a different purpose (wrong namespace)")
    if reserved:
        raise OPBError("unexpected reserved data in SSH signature")
    if hash_alg not in (b"sha512", b"sha256"):
        raise OPBError("unsupported SSH signature hash")
    sig_reader = _Reader(sig_wire)
    if sig_reader.string() != b"ssh-ed25519":
        raise OPBError("only ssh-ed25519 signatures are supported")
    signature = sig_reader.string()
    sig_reader.finish()
    if len(signature) != 64:
        raise OPBError("malformed Ed25519 signature")
    key.verify_raw(signature, _sshsig_signed_data(ns, hash_alg, message, reserved))
    return key


def sshsig_armor(blob: bytes) -> str:
    text = b64e(blob)
    lines = [text[i:i + 70] for i in range(0, len(text), 70)]
    return "-----BEGIN SSH SIGNATURE-----\n" + "\n".join(lines) + "\n-----END SSH SIGNATURE-----\n"


# --------------------------------------------------------------------------
# DSSE envelopes
# --------------------------------------------------------------------------

def pae(payload_type: str, payload: bytes) -> bytes:
    """DSSE pre-authentication encoding."""
    t = payload_type.encode()
    return b"DSSEv1 %d %s %d %s" % (len(t), t, len(payload), payload)


def make_envelope(statement: dict, privates: list, namespace: str) -> dict:
    payload = canonical(statement)
    message = pae(PAYLOAD_TYPE, payload)
    signatures = [{"keyid": public_of(k).fingerprint, "sig": b64e(sshsig_sign(k, message, namespace))}
                  for k in privates]
    return {"payloadType": PAYLOAD_TYPE, "payload": b64e(payload), "signatures": signatures}


def envelope_digest(envelope: dict) -> str:
    return sha256_hex(canonical(envelope))


def open_envelope(envelope, namespace: str, multi: bool = False):
    """Check an envelope's signatures. Returns (statement, [signer PublicKey])."""
    if not isinstance(envelope, dict) or set(envelope) != {"payloadType", "payload", "signatures"}:
        raise OPBError("envelope must have exactly payloadType, payload and signatures")
    if envelope["payloadType"] != PAYLOAD_TYPE:
        raise OPBError("unexpected payloadType")
    payload = b64d(envelope["payload"])
    statement = parse_json(payload)
    if canonical(statement) != payload:
        raise OPBError("payload is not in canonical JSON form")
    sigs = envelope["signatures"]
    if not isinstance(sigs, list) or not sigs:
        raise OPBError("envelope has no signatures")
    if not multi and len(sigs) != 1:
        raise OPBError("events must carry exactly one signature")
    message = pae(PAYLOAD_TYPE, payload)
    signers, seen = [], set()
    for sig in sigs:
        if not isinstance(sig, dict) or set(sig) != {"keyid", "sig"}:
            raise OPBError("each signature needs exactly keyid and sig")
        key = sshsig_verify(b64d(sig["sig"]), message, namespace)
        if sig["keyid"] != key.fingerprint:
            raise OPBError("signature keyid does not match the signing key")
        if key.fingerprint in seen:
            raise OPBError("the same key signed twice")
        seen.add(key.fingerprint)
        signers.append(key)
    return statement, signers


# --------------------------------------------------------------------------
# Statements and their schema (schemas/predicates.json)
# --------------------------------------------------------------------------

def _check_field(name: str, rule: dict, value) -> None:
    kind = rule["type"]
    if kind == "id":
        ok = isinstance(value, str) and bool(ID_RE.match(value))
    elif kind == "text":
        ok = (isinstance(value, str) and 0 < len(value) <= rule.get("max", 1000)
              and not any(ord(c) < 32 and c not in "\n\t" for c in value))
    elif kind == "enum":
        ok = value in rule["values"]
    elif kind == "int":
        ok = (isinstance(value, int) and not isinstance(value, bool)
              and rule.get("min", -2**53) <= value <= rule.get("max", 2**53))
    elif kind == "list":
        ok = (isinstance(value, list) and value and len(set(value)) == len(value)
              and all(v in rule["values"] for v in value))
    elif kind == "time":
        try:
            parse_time(value)
            ok = True
        except OPBError:
            ok = False
    elif kind == "digest":
        ok = isinstance(value, str) and bool(DIGEST_RE.match(value))
    else:
        raise OPBError(f"schema error: unknown field type {kind!r}")
    if not ok:
        raise OPBError(f"field {name!r} is invalid ({kind}: {str(value)[:60]!r})")


def check_statement(statement, spec: dict):
    """Validate an in-toto Statement against the book's schema.

    Returns (event_type, subjects, predicate).
    """
    if not isinstance(statement, dict) or set(statement) != {"_type", "subject", "predicateType", "predicate"}:
        raise OPBError("statement must have exactly _type, subject, predicateType and predicate")
    if statement["_type"] != STATEMENT_TYPE:
        raise OPBError("statement _type must be in-toto Statement v1")
    ptype = statement["predicateType"]
    suffix = ":v" + spec["spec_version"]
    if not isinstance(ptype, str) or not ptype.startswith(PREDICATE_PREFIX) or not ptype.endswith(suffix):
        raise OPBError(f"unsupported predicateType {str(ptype)[:80]!r}")
    etype = ptype[len(PREDICATE_PREFIX):-len(suffix)]
    if etype not in spec["types"]:
        raise OPBError(f"unknown event type {etype!r}")
    type_spec = spec["types"][etype]

    subjects = statement["subject"]
    if not isinstance(subjects, list) or not subjects:
        raise OPBError("subject must be a non-empty list")
    for s in subjects:
        if (not isinstance(s, dict) or set(s) != {"name", "digest"} or not isinstance(s["name"], str)
                or not isinstance(s["digest"], dict) or set(s["digest"]) != {"sha256"}
                or not isinstance(s["digest"]["sha256"], str) or not HEX64_RE.match(s["digest"]["sha256"])):
            raise OPBError("each subject needs a name and a sha256 digest")
    kind = type_spec["subject"]
    if kind != "files" and len(subjects) != 1:
        raise OPBError(f"{etype} events have exactly one subject")
    name = subjects[0]["name"]
    hexd = subjects[0]["digest"]["sha256"]
    if kind == "entry":
        if not name.startswith("entry:") or not ID_RE.match(name[6:]):
            raise OPBError("subject must be named entry:<entry-id>")
    elif kind == "key":
        if not name.startswith("key:SHA256:"):
            raise OPBError("subject must be named key:SHA256:<fingerprint>")
        if name[4:] != "SHA256:" + b64e(bytes.fromhex(hexd)).rstrip("="):
            raise OPBError("key subject name and digest disagree")
    elif kind == "event":
        if name != "event:" + hexd:
            raise OPBError("subject must be named event:<event digest>")
    elif kind == "log":
        if not name.startswith("log:"):
            raise OPBError("subject must be named log:<collection>")
    elif kind == "files":
        names = [s["name"] for s in subjects]
        if len(set(names)) != len(names):
            raise OPBError("duplicate file subjects")

    predicate = statement["predicate"]
    if not isinstance(predicate, dict):
        raise OPBError("predicate must be an object")
    rules = dict(spec["common_fields"])
    rules.update(type_spec["fields"])
    unknown = set(predicate) - set(rules)
    if unknown:
        raise OPBError(f"unknown predicate field(s): {', '.join(sorted(unknown))}")
    for field, rule in rules.items():
        if field not in predicate:
            if not rule.get("optional"):
                raise OPBError(f"missing required field {field!r}")
            continue
        _check_field(field, rule, predicate[field])
    return etype, subjects, predicate


def build_statement(etype: str, subjects: list, predicate: dict, spec: dict) -> dict:
    return {
        "_type": STATEMENT_TYPE,
        "subject": subjects,
        "predicateType": f"{PREDICATE_PREFIX}{etype}:v{spec['spec_version']}",
        "predicate": predicate,
    }


# --------------------------------------------------------------------------
# Entries (content-addressed folders)
# --------------------------------------------------------------------------

def entry_manifest(folder: Path) -> dict:
    folder = Path(folder)
    entry_id = folder.name
    if not ID_RE.match(entry_id):
        raise OPBError(f"entry folder name {entry_id!r} must be lowercase letters, digits and hyphens")
    if not folder.is_dir():
        raise OPBError(f"not a folder: {folder}")
    files = {}
    for path in sorted(folder.rglob("*")):
        rel = path.relative_to(folder).as_posix()
        if any(part.startswith(".") for part in rel.split("/")):
            continue
        if path.is_symlink():
            raise OPBError(f"symbolic links are not allowed in entries: {rel}")
        if path.is_file():
            files[rel] = sha256_hex(path.read_bytes())
    if not files:
        raise OPBError(f"entry {entry_id} has no files")
    return {"entry_id": entry_id, "files": files}


def entry_digest(folder: Path) -> str:
    return sha256_hex(canonical(entry_manifest(folder)))


# --------------------------------------------------------------------------
# Merkle tree (RFC 6962 hashing)
# --------------------------------------------------------------------------

def merkle_root(leaves: list) -> bytes:
    n = len(leaves)
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return hashlib.sha256(b"\x00" + leaves[0]).digest()
    k = 1 << ((n - 1).bit_length() - 1)
    return hashlib.sha256(b"\x01" + merkle_root(leaves[:k]) + merkle_root(leaves[k:])).digest()


# --------------------------------------------------------------------------
# Registry: members, policy and schema
# --------------------------------------------------------------------------

class Registry:
    def __init__(self, repo: Path):
        self.repo = repo
        self.raw = {}
        for rel in REGISTRY_FILES:
            path = repo / rel
            try:
                self.raw[rel] = path.read_bytes()
            except FileNotFoundError:
                raise OPBError(f"missing registry file {rel}") from None
        members_doc = parse_json(self.raw["governance/members.json"])
        self.policy = parse_json(self.raw["governance/policy.json"])
        self.spec = parse_json(self.raw["schemas/predicates.json"])
        self._check_policy()
        self.collection = self.policy["collection"]
        self.namespace = self.policy["namespace"]
        self.members = {}
        self.key_index = {}  # fingerprint -> (member id, retired_before_log_size or None)
        if not isinstance(members_doc, dict) or not isinstance(members_doc.get("members"), list):
            raise OPBError("members.json must contain a members list")
        for m in members_doc["members"]:
            self._add_member(m)

    def _check_policy(self) -> None:
        p, s = self.policy, self.spec
        for key in ("policy_version", "collection", "namespace", "registry_threshold", "roles",
                    "delegable", "delegation_max_days", "max_future_skew_hours",
                    "max_sequencing_age_hours", "admission", "front_page_size"):
            if key not in p:
                raise OPBError(f"policy.json is missing {key!r}")
        if not ID_RE.match(str(p["collection"])):
            raise OPBError("policy collection must be a simple id")
        if not isinstance(s.get("types"), dict) or "spec_version" not in s:
            raise OPBError("predicates.json is malformed")
        for name, role in p["roles"].items():
            for t in role.get("may", []):
                if t not in s["types"]:
                    raise OPBError(f"policy role {name} allows unknown event type {t}")
        for t in p["delegable"]:
            if t in ("delegation", "revocation", "review", "quarantine", "checkpoint", "registry"):
                raise OPBError(f"{t} events may never be delegated to agents")
        if p["admission"].get("test_min_role") not in p["roles"]:
            raise OPBError("admission.test_min_role must name a role")

    def _add_member(self, m) -> None:
        if not isinstance(m, dict):
            raise OPBError("each member must be an object")
        mid = m.get("id")
        if not isinstance(mid, str) or not ID_RE.match(mid):
            raise OPBError(f"invalid member id {mid!r}")
        if mid in self.members:
            raise OPBError(f"duplicate member {mid}")
        if m.get("role") not in self.policy["roles"]:
            raise OPBError(f"member {mid} has unknown role {m.get('role')!r}")
        if m.get("status", "active") not in ("active", "suspended"):
            raise OPBError(f"member {mid} has unknown status")
        for scope in m.get("review_scopes", []):
            if scope not in ("content", "security", "accessibility"):
                raise OPBError(f"member {mid} has unknown review scope {scope!r}")
        self.members[mid] = m

        def index(line, retired):
            fpr = PublicKey.from_line(line).fingerprint
            if fpr in self.key_index:
                raise OPBError(f"key {fpr} is listed more than once")
            self.key_index[fpr] = (mid, retired)

        for line in m.get("keys", []):
            index(line, None)
        for rk in m.get("retired_keys", []):
            n = rk.get("valid_before_log_size")
            if not isinstance(n, int) or n < 0:
                raise OPBError(f"member {mid}: retired key needs valid_before_log_size")
            index(rk.get("key", ""), n)

    def rank(self, role: str) -> int:
        return self.policy["roles"][role]["rank"]

    def may(self, member: dict, etype: str) -> bool:
        return etype in self.policy["roles"][member["role"]].get("may", [])

    def file_digests(self) -> dict:
        return {rel: sha256_hex(self.raw[rel]) for rel in REGISTRY_FILES}


def check_registry_signature(repo: Path, reg: Registry, root: str | None) -> dict:
    trust = {"registry_signature": "missing", "signers": [], "threshold": reg.policy["registry_threshold"],
             "root_pinned": bool(root), "root_match": None, "warnings": [], "errors": []}
    path = repo / REGISTRY_SIG
    if not path.exists():
        trust["errors"].append("The registry is not signed yet. The founder runs: opb init")
        return trust
    try:
        statement, signers = open_envelope(read_json(path), reg.namespace, multi=True)
        etype, subjects, predicate = check_statement(statement, reg.spec)
        if etype != "registry":
            raise OPBError("registry signature file holds the wrong statement type")
        if predicate["collection"] != reg.collection:
            raise OPBError("registry signature is for a different collection")
        signed = {s["name"]: s["digest"]["sha256"] for s in subjects}
        if signed != reg.file_digests():
            raise OPBError("members, policy or schema changed since the registry was signed")
        member_ids = []
        for key in signers:
            owner = reg.key_index.get(key.fingerprint)
            if not owner or owner[1] is not None:
                raise OPBError(f"registry signer {key.fingerprint} is not a current member key")
            member = reg.members[owner[0]]
            if member["role"] != "S" or member.get("status", "active") != "active":
                raise OPBError(f"registry signer {owner[0]} is not an active S-tier steward")
            member_ids.append(owner[0])
        if predicate["actor"] not in member_ids:
            raise OPBError("registry actor is not one of its signers")
        trust["signers"] = sorted(member_ids)
        if len(set(member_ids)) < reg.policy["registry_threshold"]:
            raise OPBError(f"registry needs {reg.policy['registry_threshold']} steward signature(s)")
        if root:
            trust["root_match"] = root in [k.fingerprint for k in signers]
            if not trust["root_match"]:
                raise OPBError("registry is not signed by your pinned trust root")
        else:
            trust["warnings"].append(
                "Trust root not pinned. Pass --root <steward key fingerprint> so a copy of this "
                "repository with replaced members cannot fool you.")
        if reg.policy["registry_threshold"] < 2:
            trust["warnings"].append(
                "Bootstrap mode: a single steward signature controls the registry.")
        trust["registry_signature"] = "valid"
    except OPBError as exc:
        trust["registry_signature"] = "invalid"
        trust["errors"].append(f"Registry signature: {exc}")
    return trust


# --------------------------------------------------------------------------
# Ledger replay
# --------------------------------------------------------------------------

class Event:
    def __init__(self, digest: str, source: str):
        self.digest = digest          # hex sha256 of the canonical envelope
        self.source = source
        self.envelope = None
        self.etype = None
        self.subjects = []
        self.predicate = {}
        self.actor = None
        self.signer = None
        self.created = None
        self.log_index = None
        self.order = None
        self.valid = True
        self.reason = None
        self.direct = False
        self.via = None               # delegation event used, if any
        self.withdrawn_by = None

    def fail(self, reason: str) -> None:
        if self.valid:
            self.valid, self.reason = False, reason

    @property
    def subject_name(self) -> str:
        return self.subjects[0]["name"] if self.subjects else ""

    @property
    def subject_hex(self) -> str:
        return self.subjects[0]["digest"]["sha256"] if self.subjects else ""


def read_log(repo: Path) -> list:
    path = repo / LOG_FILE
    if not path.exists():
        return []
    lines = [ln.strip() for ln in path.read_text(encoding="utf-8").splitlines()]
    lines = [ln for ln in lines if ln]
    for ln in lines:
        if not DIGEST_RE.match(ln):
            raise OPBError(f"log.txt has a malformed line: {ln[:80]!r}")
    if len(set(lines)) != len(lines):
        raise OPBError("log.txt lists an event twice")
    return [ln[7:] for ln in lines]


def load_events(repo: Path, reg: Registry, extra: list | None = None) -> list:
    events = []
    max_bytes = reg.spec.get("max_event_bytes", 16384)
    items = []
    for path in sorted((repo / EVENTS_DIR).glob("*.json")):
        items.append((path.name, path.read_bytes(), path.stem))
    for envelope in extra or []:
        raw = canonical(envelope)
        items.append(("(new event)", raw, envelope_digest(envelope)))
    for source, raw, expected in items:
        event = Event(expected, source)
        events.append(event)
        if len(raw) > max_bytes:
            event.fail(f"event file is larger than {max_bytes} bytes")
            continue
        try:
            event.envelope = parse_json(raw)
            event.digest = envelope_digest(event.envelope)
            if event.digest != expected:
                raise OPBError("file name does not match the event's digest")
            statement, signers = open_envelope(event.envelope, reg.namespace)
            event.signer = signers[0]
            event.etype, event.subjects, event.predicate = check_statement(statement, reg.spec)
            event.actor = event.predicate["actor"]
            event.created = parse_time(event.predicate["created_at"])
        except OPBError as exc:
            event.fail(str(exc))
    return events


def replay(repo: Path, reg: Registry, now: dt.datetime, extra: list | None = None):
    """Validate every event and return (events, log, integrity_errors)."""
    integrity = []
    try:
        log = read_log(repo)
    except OPBError as exc:
        integrity.append(str(exc))
        log = []
    events = load_events(repo, reg, extra)
    by_digest = {}
    for e in events:
        if e.digest in by_digest:
            e.fail("duplicate event")
        by_digest.setdefault(e.digest, e)
    for i, d in enumerate(log):
        if d not in by_digest:
            integrity.append(f"log.txt references a missing event sha256:{d}")
        else:
            by_digest[d].log_index = i

    # Sealed events keep their log order. Pending events sort by time; within
    # the same second, delegations go first and revocations last, so an event
    # signed right after its delegation (or revoked right after) orders correctly.
    tie = {"delegation": 0, "revocation": 2}

    def sort_key(e):
        if e.log_index is not None:
            return (0, e.log_index, 0, "")
        return (1, fmt_time(e.created) if e.created else "", tie.get(e.etype, 1), e.digest)

    events.sort(key=sort_key)
    for i, e in enumerate(events):
        e.order = i

    skew = dt.timedelta(hours=reg.policy["max_future_skew_hours"])
    delegable = set(reg.policy["delegable"])

    # Pass 1: identity, role, and type rules that do not depend on other events.
    for e in events:
        if not e.valid:
            continue
        if e.etype in LEDGER_ONLY_TYPES:
            e.fail(f"{e.etype} statements do not belong in ledger/events")
            continue
        p = e.predicate
        if p["collection"] != reg.collection:
            e.fail("event belongs to a different collection")
            continue
        if e.created > now + skew:
            e.fail("created_at is in the future")
            continue
        member = reg.members.get(e.actor)
        if member is None:
            e.fail(f"unknown member {e.actor!r}")
            continue
        if member.get("status", "active") != "active":
            e.fail(f"member {e.actor} is suspended")
            continue
        if not reg.may(member, e.etype):
            e.fail(f"role {member['role']} may not sign {e.etype} events")
            continue
        owner = reg.key_index.get(e.signer.fingerprint)
        if owner and owner[0] == e.actor:
            retired_before = owner[1]
            if retired_before is not None and (e.log_index is None or e.log_index >= retired_before):
                e.fail("signed with a retired key after its retirement point")
                continue
            e.direct = True
        elif owner:
            e.fail("signed with a key that belongs to a different member")
            continue
        elif e.etype not in delegable:
            e.fail(f"{e.etype} events must be signed with the member's own key, not an agent key")
            continue
        if e.etype == "review":
            missing = set(p["scopes"]) - set(member.get("review_scopes", []))
            if missing:
                e.fail(f"{e.actor} is not appointed to review: {', '.join(sorted(missing))}")
        elif e.etype == "delegation":
            expires = parse_time(p["expires"])
            if expires <= e.created:
                e.fail("delegation expires before it starts")
            elif expires - e.created > dt.timedelta(days=reg.policy["delegation_max_days"]):
                e.fail(f"delegations may last at most {reg.policy['delegation_max_days']} days")
            elif e.subject_name[4:] in reg.key_index:
                e.fail("cannot delegate to a key that already belongs to a member")
            elif set(p["scopes"]) - delegable:
                e.fail("delegation grants an event type that policy does not allow agents to sign")

    # Pass 2: events signed by agent keys need a valid, earlier delegation.
    delegations = [d for d in events if d.valid and d.etype == "delegation"]
    for e in events:
        if not e.valid or e.direct:
            continue
        match = None
        for d in delegations:
            if (d.actor == e.actor and d.subject_name == "key:" + e.signer.fingerprint
                    and e.etype in d.predicate["scopes"] and d.order < e.order
                    and d.created <= e.created <= parse_time(d.predicate["expires"])):
                match = d
        if match is None:
            e.fail("agent key has no valid delegation from this member for this event type and time")
        else:
            e.via = match.digest

    # Pass 3: revocations (always signed directly by the member).
    for r in events:
        if not r.valid or r.etype != "revocation":
            continue
        target = by_digest.get(r.subject_hex)
        if target is None or not target.valid:
            r.fail("revokes an unknown or invalid event")
        elif target.actor != r.actor:
            r.fail("members can only revoke their own events")
        elif target.etype in ("revocation", "quarantine"):
            r.fail(f"{target.etype} events cannot be revoked")
        elif target.order > r.order:
            r.fail("revocation comes before the event it revokes")
        elif target.withdrawn_by is None:
            target.withdrawn_by = r.digest

    # Pass 4: everything signed under a revoked delegation is void.
    for e in events:
        if e.valid and e.via and by_digest[e.via].withdrawn_by:
            e.fail("the delegation this agent relied on was revoked")
    return events, log, integrity


def check_checkpoints(repo: Path, reg: Registry, log: list):
    """Verify every signed checkpoint against the log. Returns (latest, errors)."""
    errors, latest = [], None
    leaves = [bytes.fromhex(d) for d in log]
    for path in sorted((repo / CHECKPOINT_DIR).glob("*.json")):
        try:
            statement, signers = open_envelope(read_json(path), reg.namespace)
            etype, subjects, p = check_statement(statement, reg.spec)
            if etype != "checkpoint":
                raise OPBError("not a checkpoint")
            if subjects[0]["name"] != "log:" + reg.collection or p["collection"] != reg.collection:
                raise OPBError("checkpoint is for a different collection")
            owner = reg.key_index.get(signers[0].fingerprint)
            member = reg.members.get(p["actor"])
            if (not owner or owner[0] != p["actor"] or owner[1] is not None or member is None
                    or not reg.may(member, "checkpoint") or member.get("status", "active") != "active"):
                raise OPBError("checkpoint is not signed by an active steward key")
            size = p["size"]
            if path.name != f"{size:08d}.json":
                raise OPBError("checkpoint file name does not match its size")
            if size > len(log):
                raise OPBError(f"checkpoint covers {size} events but the log has only {len(log)} (rollback?)")
            if merkle_root(leaves[:size]).hex() != subjects[0]["digest"]["sha256"]:
                raise OPBError("log history was changed after this checkpoint was signed")
            if latest is None or size > latest["size"]:
                latest = {"size": size, "root": subjects[0]["digest"]["sha256"],
                          "signer": p["actor"], "created_at": p["created_at"], "file": path.name}
        except OPBError as exc:
            errors.append(f"Checkpoint {path.name}: {exc}")
    return latest, errors


def check_state(state_path: str | None, reg: Registry, log: list, latest) -> tuple:
    """Compare against the last checkpoint this verifier accepted (rollback/fork detection)."""
    if not state_path:
        return "not_checked", []
    path = Path(state_path).expanduser()
    if not path.exists():
        return "first_run", []
    try:
        state = read_json(path)
        size, root = state["size"], state["root"]
        if state.get("collection") != reg.collection:
            return "error", ["State file is for a different collection"]
    except (OPBError, KeyError, TypeError):
        return "error", ["State file is unreadable"]
    if size > len(log) or merkle_root([bytes.fromhex(d) for d in log[:size]]).hex() != root:
        return "ROLLBACK_OR_FORK", [
            "This copy of the ledger does not extend the history you verified before. "
            "Someone rewrote or rolled back the log. Do not trust this copy."]
    if latest is None or latest["size"] < size:
        return "ROLLBACK_OR_FORK", ["This copy is missing checkpoints you have already seen."]
    return "ok", []


# --------------------------------------------------------------------------
# Tally: turn valid events into entry status, next steps and a front page
# --------------------------------------------------------------------------

def tally(reg: Registry, events: list) -> dict:
    adm = reg.policy["admission"]
    test_rank = reg.rank(adm["test_min_role"])
    versions = {}  # (entry_id, hex) -> list of events (in order)
    for e in events:
        if e.valid and not e.withdrawn_by and e.subject_name.startswith("entry:"):
            versions.setdefault((e.subject_name[6:], e.subject_hex), []).append(e)

    entries = {}
    for (entry_id, hexd), evs in versions.items():
        subs = [e for e in evs if e.etype == "submission"]
        info = {"digest": "sha256:" + hexd, "submitted": bool(subs), "author": None, "route": None,
                "first_order": subs[0].order if subs else None, "title": None}
        author = None
        if subs:
            author = subs[0].actor
            info.update(author=author, route=subs[0].predicate["route"],
                        title=subs[0].predicate["title"],
                        submitted_at=subs[0].predicate["created_at"])

        def latest_per_actor(kind):
            out = {}
            for e in evs:
                if e.etype == kind:
                    out[e.actor] = e
            return out

        votes = {a: e for a, e in latest_per_actor("vote").items() if a != author}
        dist = [0] * 6
        for e in votes.values():
            dist[e.predicate["score"]] += 1
        count = len(votes)
        mean = round(sum(i * n for i, n in enumerate(dist)) / count, 2) if count else None
        info["votes"] = {"count": count, "mean": mean, "distribution": dist,
                         "excluded_author_vote": author in latest_per_actor("vote")}

        tests = latest_per_actor("test")
        counted = {a: e for a, e in tests.items() if reg.rank(reg.members[a]["role"]) >= test_rank}
        passing = sorted(a for a, e in counted.items() if e.predicate["result"] == "pass")
        failing = sorted(a for a, e in counted.items() if e.predicate["result"] == "fail")
        nonauthor_pass = [a for a in passing if a != author]
        info["tests"] = {"passing": len(passing), "nonauthor_passing": len(nonauthor_pass),
                         "failing": len(failing), "testers": sorted(counted)}

        reviews = {a: e for a, e in latest_per_actor("review").items() if a != author}
        approvals = {a: e for a, e in reviews.items() if e.predicate["decision"] == "approve"}
        blocks = sorted(a for a, e in reviews.items() if e.predicate["decision"] == "block")
        changes = sorted(a for a, e in reviews.items() if e.predicate["decision"] == "request_changes")
        covered = sorted({s for e in approvals.values() for s in e.predicate["scopes"]})
        info["reviews"] = {"approvals": len(approvals), "approvers": sorted(approvals),
                           "scopes_covered": covered, "blocked_by": blocks, "changes_requested_by": changes}

        quarantine = None
        for e in evs:
            if e.etype == "quarantine":
                quarantine = e.predicate["action"]

        steps = []
        if not subs:
            status = "not_submitted"
            steps.append("No submission statement exists for this exact version.")
        elif quarantine == "quarantine":
            status = "quarantined"
            steps.append("A steward quarantined this version while a concern is investigated.")
        elif blocks:
            status = "blocked"
            steps.append("A reviewer blocked this version. Fix the concern and submit a new version.")
        else:
            missing_scopes = [s for s in adm["required_review_scopes"] if s not in covered]
            if len(passing) < adm["min_passing_tests"]:
                steps.append(f"Needs {adm['min_passing_tests'] - len(passing)} more passing test "
                             f"report(s) from members at '{adm['test_min_role']}' tier or above.")
            if len(nonauthor_pass) < adm["min_nonauthor_passing_tests"]:
                steps.append("Needs a passing test from someone other than the author.")
            if len(approvals) < adm["min_approvals"]:
                steps.append(f"Needs {adm['min_approvals'] - len(approvals)} more approving review(s) "
                             "from independent reviewers.")
            if missing_scopes:
                steps.append(f"Needs an approving review covering: {', '.join(missing_scopes)}.")
            if changes:
                steps.append("Reviewers requested changes; consider submitting an improved version.")
            status = "qualified" if not [s for s in steps if s.startswith("Needs")] else "submitted"
            if status == "qualified":
                steps.insert(0, "Qualified. Community votes decide its place on the front page.")
        info["status"] = status
        info["next_steps"] = steps
        entries.setdefault(entry_id, []).append(info)

    front = []
    for entry_id, infos in entries.items():
        infos.sort(key=lambda i: (i["first_order"] is None, i["first_order"] or 0))
        submitted = [i for i in infos if i["submitted"]]
        for older, newer in zip(submitted, submitted[1:]):
            older["superseded_by"] = newer["digest"]
        qualified = [i for i in submitted if i["status"] == "qualified"]
        if qualified:
            best = qualified[-1]
            front.append({"entry_id": entry_id, "digest": best["digest"],
                          "vote_mean": best["votes"]["mean"], "vote_count": best["votes"]["count"]})
    front.sort(key=lambda f: (-(f["vote_mean"] or 0), -f["vote_count"], f["entry_id"]))
    return {"entries": entries, "front_page": front[:reg.policy["front_page_size"]]}


def working_copies(repo: Path, entries: dict) -> dict:
    out = {}
    base = repo / ENTRIES_DIR
    if not base.is_dir():
        return out
    for folder in sorted(p for p in base.iterdir() if p.is_dir() and not p.name.startswith(".")):
        try:
            d = "sha256:" + entry_digest(folder)
        except OPBError as exc:
            out[folder.name] = {"error": str(exc)}
            continue
        known = {i["digest"]: i for i in entries.get(folder.name, [])}
        info = known.get(d)
        route = "improve" if any(i["submitted"] for i in known.values()) else "new"
        out[folder.name] = {
            "digest": d,
            "matches_submitted_version": bool(info and info["submitted"]),
            "next_step": None if info and info["submitted"] else
            f"Files in entries/{folder.name} are not submitted yet: "
            f"opb attest submission --entry entries/{folder.name} --set route={route} --set title=\"...\"",
        }
    return out


# --------------------------------------------------------------------------
# Whole-repository analysis
# --------------------------------------------------------------------------

def analyze(repo: Path, root: str | None = None, state: str | None = None, now: dt.datetime | None = None,
            extra: list | None = None, show_text: bool = False) -> tuple:
    now = now or now_utc()
    report = {"tool_version": TOOL_VERSION, "checked_at": fmt_time(now), "integrity_ok": False,
              "note": SAFETY_NOTE}
    try:
        reg = Registry(repo)
    except OPBError as exc:
        report["errors"] = [f"Registry: {exc}"]
        return report, None, []
    report["collection"] = reg.collection
    report["policy_version"] = reg.policy["policy_version"]
    trust = check_registry_signature(repo, reg, root)
    events, log, integrity = replay(repo, reg, now, extra)
    latest, cp_errors = check_checkpoints(repo, reg, log)
    state_status, state_errors = check_state(state, reg, log, latest)
    errors = trust.pop("errors") + integrity + cp_errors + state_errors
    report["trust"] = trust

    valid = [e for e in events if e.valid]
    report["ledger"] = {
        "events": len(events), "valid": len(valid), "invalid": len(events) - len(valid),
        "withdrawn": sum(1 for e in valid if e.withdrawn_by),
        "log_size": len(log),
        "pending_sequencing": sum(1 for e in events if e.log_index is None),
        "checkpoint": latest,
        "not_yet_checkpointed": len(log) - (latest["size"] if latest else 0),
        "state_check": state_status,
    }
    report["invalid_events"] = [{"event": "sha256:" + e.digest, "file": e.source, "reason": e.reason}
                                for e in events if not e.valid]
    t = tally(reg, events)
    if not show_text:
        for infos in t["entries"].values():
            for i in infos:
                i.pop("title", None)
    report["entries"] = t["entries"]
    report["front_page"] = t["front_page"]
    report["working_copy"] = working_copies(repo, t["entries"])
    report["errors"] = errors
    report["integrity_ok"] = not errors
    return report, reg, events


def exit_code(report: dict) -> int:
    if not report.get("integrity_ok"):
        return 2
    if report.get("invalid_events"):
        return 1
    return 0


def print_report(report: dict) -> None:
    out = []
    ok = report.get("integrity_ok")
    out.append(f"The Open Prompt Book - verification ({report.get('collection', '?')}, "
               f"policy {report.get('policy_version', '?')}, opb {report['tool_version']})")
    out.append("")
    out.append("INTEGRITY: " + ("OK" if ok else "PROBLEMS FOUND"))
    for err in report.get("errors", []):
        out.append(f"  ! {err}")
    trust = report.get("trust")
    if trust:
        out.append(f"Registry signature: {trust['registry_signature']}"
                   + (f" (signed by {', '.join(trust['signers'])})" if trust["signers"] else ""))
        for w in trust["warnings"]:
            out.append(f"  - {w}")
    led = report.get("ledger")
    if led:
        cp = led["checkpoint"]
        out.append(f"Ledger: {led['valid']} valid, {led['invalid']} invalid, {led['withdrawn']} withdrawn; "
                   f"{led['pending_sequencing']} waiting to be sequenced")
        out.append("Checkpoint: " + (f"{cp['size']} events, root {cp['root'][:16]}..., signed by {cp['signer']}"
                                     if cp else "none yet")
                   + f"; history check: {led['state_check']}")
    for bad in report.get("invalid_events", []):
        out.append(f"  x {bad['file']}: {bad['reason']}")
    entries = report.get("entries", {})
    if entries:
        out.append("")
        out.append("ENTRIES")
        for entry_id in sorted(entries):
            for v in entries[entry_id]:
                votes = v["votes"]
                vote_text = f"{votes['mean']}/5 from {votes['count']}" if votes["count"] else "no votes"
                title = f" \"{v['title']}\" (untrusted text)" if v.get("title") else ""
                out.append(f"- {entry_id} {v['digest'][7:19]}{title}: {v['status'].upper()}")
                out.append(f"    tests passing {v['tests']['passing']} (non-author {v['tests']['nonauthor_passing']}), "
                           f"approvals {v['reviews']['approvals']} {v['reviews']['scopes_covered']}, votes {vote_text}")
                if v.get("superseded_by"):
                    out.append(f"    superseded by {v['superseded_by'][7:19]}")
                for step in v["next_steps"]:
                    out.append(f"    > {step}")
    wc = report.get("working_copy", {})
    pending = [(k, w) for k, w in wc.items() if w.get("next_step") or w.get("error")]
    if pending:
        out.append("")
        out.append("UNSUBMITTED CHANGES")
        for k, w in pending:
            out.append(f"- {k}: {w.get('error') or w['next_step']}")
    out.append("")
    out.append("FRONT PAGE")
    if report.get("front_page"):
        for n, f in enumerate(report["front_page"], 1):
            out.append(f"{n}. {f['entry_id']} ({f['digest'][7:19]}) - {f['vote_mean']}/5 from {f['vote_count']} vote(s)")
    else:
        out.append("No qualified entries yet.")
    out.append("")
    out.append(report["note"])
    print("\n".join(out))


# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------

def _repo(args) -> Path:
    return Path(args.repo).resolve()


def _now(args) -> dt.datetime:
    return now_utc(getattr(args, "now", None))


def _parse_sets(pairs: list, rules: dict) -> dict:
    out = {}
    for pair in pairs or []:
        if "=" not in pair:
            raise OPBError(f"--set expects field=value, got {pair!r}")
        key, value = pair.split("=", 1)
        rule = rules.get(key)
        if rule is None:
            raise OPBError(f"unknown field {key!r}; allowed: {', '.join(sorted(rules))}")
        if rule["type"] == "int":
            try:
                value = int(value)
            except ValueError:
                raise OPBError(f"{key} must be a whole number") from None
        elif rule["type"] == "list":
            value = [v.strip() for v in value.split(",") if v.strip()]
        out[key] = value
    return out


def cmd_verify(args) -> int:
    report, reg, _ = analyze(_repo(args), args.root, args.state, _now(args), show_text=args.show_text)
    if args.update_state and report.get("integrity_ok") and report["ledger"]["checkpoint"]:
        cp = report["ledger"]["checkpoint"]
        write_json(Path(args.state).expanduser(),
                   {"collection": report["collection"], "size": cp["size"], "root": cp["root"]})
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print_report(report)
    return exit_code(report)


def cmd_hash(args) -> int:
    folder = Path(args.entry)
    manifest = entry_manifest(folder)
    print(json.dumps({"entry_id": manifest["entry_id"], "digest": "sha256:" + entry_digest(folder),
                      "files": manifest["files"]}, indent=2))
    return 0


def cmd_keygen(args) -> int:
    out = Path(args.out).expanduser()
    if out.exists() and not args.force:
        raise OPBError(f"{out} already exists (use --force to overwrite)")
    key = Ed25519PrivateKey.generate()
    password = os.environ.get("OPB_KEY_PASSPHRASE")
    enc = (serialization.BestAvailableEncryption(password.encode()) if password
           else serialization.NoEncryption())
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, enc))
    os.chmod(out, 0o600)
    pub = public_of(key)
    Path(str(out) + ".pub").write_text(pub.line(args.comment) + "\n", encoding="utf-8")
    print(f"Private key: {out} (keep it secret; never paste it into a chat)")
    print(f"Public key:  {out}.pub")
    print(f"Fingerprint: {pub.fingerprint}")
    return 0


def _sign_registry(repo: Path, key: Ed25519PrivateKey, actor: str, now: dt.datetime, note: str | None) -> dict:
    reg = Registry(repo)
    digests = reg.file_digests()
    subjects = [{"name": rel, "digest": {"sha256": digests[rel]}} for rel in REGISTRY_FILES]
    path = repo / REGISTRY_SIG
    message_payload = None
    if path.exists():
        try:
            existing = read_json(path)
            statement, _ = open_envelope(existing, reg.namespace, multi=True)
            if {s["name"]: s["digest"]["sha256"] for s in statement["subject"]} == digests:
                message_payload = existing  # co-sign the same statement
        except (OPBError, KeyError, TypeError):
            message_payload = None
    if message_payload is not None:
        payload = b64d(message_payload["payload"])
        fpr = public_of(key).fingerprint
        if any(s["keyid"] == fpr for s in message_payload["signatures"]):
            raise OPBError("you have already signed this registry version")
        blob = sshsig_sign(key, pae(PAYLOAD_TYPE, payload), reg.namespace)
        message_payload["signatures"].append({"keyid": fpr, "sig": b64e(blob)})
        envelope = message_payload
    else:
        predicate = {"actor": actor, "collection": reg.collection, "created_at": fmt_time(now),
                     "policy_version": reg.policy["policy_version"]}
        if note:
            predicate["note"] = note
        statement = build_statement("registry", subjects, predicate, reg.spec)
        check_statement(statement, reg.spec)
        envelope = make_envelope(statement, [key], reg.namespace)
    write_json(path, envelope)
    return envelope


def cmd_init(args) -> int:
    repo = _repo(args)
    if not ID_RE.match(args.actor):
        raise OPBError("--actor must be lowercase letters, digits and hyphens (e.g. your GitHub name)")
    members_path = repo / "governance/members.json"
    doc = read_json(members_path)
    if doc.get("members") and not args.force:
        raise OPBError("members.json already has members; use registry-sign instead (or --force)")
    key = load_private_key(args.key)
    pub = public_of(key)
    founder = {"id": args.actor, "role": "S", "status": "active", "keys": [pub.line(args.actor)],
               "review_scopes": ["content", "security", "accessibility"],
               "note": "Founding steward (bootstrap)."}
    if args.github:
        founder["github"] = args.github
    write_json(members_path, {"members": [founder]})
    _sign_registry(repo, key, args.actor, _now(args), "Founding registry.")
    print(f"Registry created and signed by {args.actor}.")
    print(f"Your trust-root fingerprint: {pub.fingerprint}")
    print("Publish this fingerprint somewhere other than this repository (your GitHub profile, a website).")
    print(f"Verifiers pin it with: python tools/opb.py verify --root {pub.fingerprint}")
    return 0


def cmd_registry_sign(args) -> int:
    repo = _repo(args)
    _sign_registry(repo, load_private_key(args.key), args.actor, _now(args), args.note)
    report, _, _ = analyze(repo, None, None, _now(args))
    print(f"Registry signature: {report.get('trust', {}).get('registry_signature', 'invalid')}")
    for e in report.get("errors", []):
        print(f"  ! {e}")
    return 0 if report.get("trust", {}).get("registry_signature") == "valid" else 2


def cmd_attest(args) -> int:
    repo = _repo(args)
    reg = Registry(repo)
    now = _now(args)
    etype = args.type
    if etype not in reg.spec["types"] or etype in LEDGER_ONLY_TYPES:
        raise OPBError(f"cannot attest {etype!r}")
    type_spec = reg.spec["types"][etype]
    key = load_private_key(args.key)

    kind = type_spec["subject"]
    if kind == "entry":
        if args.entry:
            folder = Path(args.entry)
            subjects = [{"name": "entry:" + folder.name, "digest": {"sha256": entry_digest(folder)}}]
        elif args.entry_id and args.digest and etype != "submission":
            if not DIGEST_RE.match(args.digest):
                raise OPBError("--digest must look like sha256:<64 hex>")
            subjects = [{"name": "entry:" + args.entry_id, "digest": {"sha256": args.digest[7:]}}]
        else:
            raise OPBError("give --entry entries/<id> (or --entry-id with --digest for an older version)")
    elif kind == "key":
        if not args.agent_pubkey:
            raise OPBError("delegations need --agent-pubkey <file.pub>")
        agent = load_public_key_file(args.agent_pubkey)
        subjects = [{"name": "key:" + agent.fingerprint, "digest": {"sha256": agent.wire_sha256}}]
    elif kind == "event":
        if not args.event or not DIGEST_RE.match(args.event):
            raise OPBError("revocations need --event sha256:<digest of the event to revoke>")
        subjects = [{"name": "event:" + args.event[7:], "digest": {"sha256": args.event[7:]}}]
    else:
        raise OPBError(f"cannot attest {etype!r}")

    predicate = {"actor": args.actor, "collection": reg.collection, "created_at": fmt_time(now),
                 "policy_version": reg.policy["policy_version"]}
    predicate.update(_parse_sets(args.set, type_spec["fields"]))
    statement = build_statement(etype, subjects, predicate, reg.spec)
    check_statement(statement, reg.spec)
    envelope = make_envelope(statement, [key], reg.namespace)
    digest = envelope_digest(envelope)

    _, _, events = analyze(repo, None, None, now, extra=[envelope])
    mine = next(e for e in events if e.digest == digest)
    result = {"event": "sha256:" + digest, "type": etype, "valid": mine.valid, "reason": mine.reason,
              "written": False}
    if mine.valid and not args.dry_run:
        write_json(repo / EVENTS_DIR / f"{digest}.json", envelope)
        result["written"] = True
        result["file"] = f"{EVENTS_DIR}/{digest}.json"
        result["next_step"] = ("Commit this file and open a pull request. Nothing is public until the "
                               "pull request is merged and a steward sequences it.")
    elif not mine.valid:
        result["next_step"] = "Nothing was written. Fix the problem above and try again."
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"{etype} event sha256:{digest[:16]}... " + ("valid" if mine.valid else f"REJECTED: {mine.reason}"))
        if result.get("file"):
            print(f"Wrote {result['file']}")
        if result.get("next_step"):
            print(result["next_step"])
    return 0 if mine.valid else 1


def cmd_sequence(args) -> int:
    repo = _repo(args)
    now = _now(args)
    reg = Registry(repo)
    key = load_private_key(args.key)
    report, _, events = analyze(repo, None, None, now)
    if report.get("trust", {}).get("registry_signature") != "valid":
        raise OPBError("refusing to sequence: the registry signature is not valid")
    if report["errors"]:
        raise OPBError("refusing to sequence while integrity problems exist: " + "; ".join(report["errors"]))
    max_age = dt.timedelta(hours=reg.policy["max_sequencing_age_hours"])
    log = read_log(repo)
    added, skipped = [], []
    for e in events:
        if e.log_index is not None:
            continue
        if not e.valid:
            skipped.append((e.source, e.reason))
        elif now - e.created > max_age:
            skipped.append((e.source, f"created_at is older than {reg.policy['max_sequencing_age_hours']} hours; "
                                      "ask the signer to sign it again"))
        else:
            added.append(e.digest)
    log.extend(added)
    (repo / LOG_FILE).write_text("".join(f"sha256:{d}\n" for d in log), encoding="utf-8")
    root = merkle_root([bytes.fromhex(d) for d in log]).hex()
    predicate = {"actor": args.actor, "collection": reg.collection, "created_at": fmt_time(now),
                 "policy_version": reg.policy["policy_version"], "size": len(log)}
    statement = build_statement("checkpoint", [{"name": "log:" + reg.collection, "digest": {"sha256": root}}],
                                predicate, reg.spec)
    check_statement(statement, reg.spec)
    write_json(repo / CHECKPOINT_DIR / f"{len(log):08d}.json", make_envelope(statement, [key], reg.namespace))
    print(f"Sequenced {len(added)} event(s); log size {len(log)}; root {root[:16]}...")
    for source, reason in skipped:
        print(f"  skipped {source}: {reason}")
    report, _, _ = analyze(repo, None, None, now)
    for e in report["errors"]:
        print(f"  ! {e}")
    return 0 if report["integrity_ok"] else 2


def cmd_show(args) -> int:
    repo = _repo(args)
    reg = Registry(repo)
    envelope = read_json(Path(args.event))
    statement, signers = open_envelope(envelope, reg.namespace, multi=True)
    print("# The signature checks out cryptographically. Whether the signer was AUTHORIZED is")
    print("# decided by `opb verify`. Free-text fields below are untrusted contributor text.")
    print(json.dumps({"event": "sha256:" + envelope_digest(envelope),
                      "signed_by": [k.fingerprint for k in signers],
                      "statement": statement}, indent=2, ensure_ascii=False))
    return 0


def cmd_export_ssh(args) -> int:
    """Write files so anyone can cross-check a signature with OpenSSH itself."""
    repo = _repo(args)
    reg = Registry(repo)
    envelope = read_json(Path(args.event))
    statement, signers = open_envelope(envelope, reg.namespace, multi=True)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "message.bin").write_bytes(pae(PAYLOAD_TYPE, b64d(envelope["payload"])))
    principals = []
    for i, (sig, key) in enumerate(zip(envelope["signatures"], signers)):
        (out / f"signature{i}.sig").write_text(sshsig_armor(b64d(sig["sig"])), encoding="ascii")
        principals.append(f'signer{i} namespaces="{reg.namespace}" {key.line()}')
    (out / "allowed_signers").write_text("\n".join(principals) + "\n", encoding="ascii")
    print(f"Wrote {out}/message.bin, signature*.sig and allowed_signers. Cross-check with:")
    print(f"  ssh-keygen -Y verify -f {out}/allowed_signers -I signer0 -n {reg.namespace} "
          f"-s {out}/signature0.sig < {out}/message.bin")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="opb", description=__doc__.split("\n")[0])
    parser.add_argument("--version", action="version", version=f"opb {TOOL_VERSION}")
    sub = parser.add_subparsers(dest="command", required=True)

    def common(p, repo=True):
        if repo:
            p.add_argument("--repo", default=".", help="path to the book repository (default: .)")
        p.add_argument("--now", help=argparse.SUPPRESS)
        return p

    p = common(sub.add_parser("verify", help="check every signature and rule; show status and next steps"))
    p.add_argument("--root", help="pinned steward key fingerprint (SHA256:...) you trust")
    p.add_argument("--state", help="file remembering the last verified checkpoint (detects rollback)")
    p.add_argument("--update-state", action="store_true", help="save the verified checkpoint to --state")
    p.add_argument("--json", action="store_true", help="machine-readable output for agents")
    p.add_argument("--show-text", action="store_true", help="include contributor free text (untrusted)")
    p.set_defaults(func=cmd_verify)

    p = common(sub.add_parser("hash", help="print an entry folder's version digest"), repo=False)
    p.add_argument("entry")
    p.set_defaults(func=cmd_hash)

    p = common(sub.add_parser("keygen", help="create an Ed25519 key (for an agent or a new member)"), repo=False)
    p.add_argument("--out", required=True)
    p.add_argument("--comment", default="")
    p.add_argument("--force", action="store_true")
    p.set_defaults(func=cmd_keygen)

    p = common(sub.add_parser("init", help="founder: create and sign the first registry"))
    p.add_argument("--key", required=True, help="your private SSH key, e.g. ~/.ssh/id_ed25519")
    p.add_argument("--actor", required=True, help="your member id (lowercase)")
    p.add_argument("--github")
    p.add_argument("--force", action="store_true")
    p.set_defaults(func=cmd_init)

    p = common(sub.add_parser("registry-sign", help="steward: sign (or co-sign) members, policy and schema"))
    p.add_argument("--key", required=True)
    p.add_argument("--actor", required=True)
    p.add_argument("--note")
    p.set_defaults(func=cmd_registry_sign)

    p = common(sub.add_parser("attest", help="sign a submission, test, review, vote, delegation, revocation or quarantine"))
    p.add_argument("type", choices=["submission", "test", "review", "vote", "delegation", "revocation", "quarantine"])
    p.add_argument("--key", required=True, help="your SSH key, or your agent's delegated key")
    p.add_argument("--actor", required=True, help="the member this statement is made for")
    p.add_argument("--entry", help="entry folder, e.g. entries/meal-planner")
    p.add_argument("--entry-id")
    p.add_argument("--digest", help="sha256:... of an older entry version")
    p.add_argument("--agent-pubkey", help="agent public key file (delegation)")
    p.add_argument("--event", help="sha256:... of the event to revoke")
    p.add_argument("--set", action="append", metavar="FIELD=VALUE")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_attest)

    p = common(sub.add_parser("sequence", help="steward: append valid pending events to the log and sign a checkpoint"))
    p.add_argument("--key", required=True)
    p.add_argument("--actor", required=True)
    p.set_defaults(func=cmd_sequence)

    p = common(sub.add_parser("show", help="decode one event file"))
    p.add_argument("event")
    p.set_defaults(func=cmd_show)

    p = common(sub.add_parser("export-ssh", help="export an event for cross-checking with ssh-keygen -Y verify"))
    p.add_argument("event")
    p.add_argument("--out", required=True)
    p.set_defaults(func=cmd_export_ssh)
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except OPBError as exc:
        print(f"opb: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())

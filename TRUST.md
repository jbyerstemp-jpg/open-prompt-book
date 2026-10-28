# How Trust Works in The Open Prompt Book

Status: specification 0.1, implemented by `tools/opb.py` 0.1.0.

This file explains, in plain language first and exact detail second, how the
book records who did what and how anyone can check it.

## The short version

- Every action (submit, test, review, vote, delegate to an agent, revoke)
  is a small **signed statement** saved as one file in `ledger/events/`.
- People sign with the **SSH key they already use for GitHub**.
- Every statement names the **exact version** of an entry by its content
  fingerprint. Change one letter and it becomes a new version; old reviews
  and votes do not carry over.
- Nobody stores a vote total. `opb verify` **replays every statement** and
  computes the totals, status and front page. Anyone gets the same answer.
- A steward periodically **seals the order** of events with a signed
  checkpoint, so history cannot be quietly rewritten.

What signatures do NOT prove: that a prompt is safe, useful, or tested
honestly. They prove who claimed what. Tests, independent reviews and votes
exist for the rest. Nothing in the book grants permission to act.

## Building blocks (all established, nothing invented)

| Need | Standard used |
| --- | --- |
| Signing keys | Ed25519 OpenSSH keys (`ssh-keygen -t ed25519`) |
| Signature format | OpenSSH SSHSIG (`ssh-keygen -Y sign/verify`), hash sha512 |
| Domain separation | SSHSIG namespace `openpromptbook-v1` |
| Signed envelope | DSSE, payload type `application/vnd.in-toto+json` |
| Statement format | in-toto Statement v1 |
| Byte-exact JSON | RFC 8785 canonical JSON, restricted: no floats, ASCII keys |
| Hash | SHA-256, always written `sha256:<hex>` |
| Log sealing | Merkle tree with RFC 6962 hashing, signed checkpoints |

Because signatures are plain SSHSIG, anyone can cross-check one with
OpenSSH itself:

```bash
python tools/opb.py export-ssh ledger/events/<id>.json --out check/
ssh-keygen -Y verify -f check/allowed_signers -I signer0 \
  -n openpromptbook-v1 -s check/signature0.sig < check/message.bin
```

CI runs this cross-check on every change (`tests/ssh_interop.py`).

## Files

| Path | Role |
| --- | --- |
| `governance/members.json` | Members, roles, public keys, review scopes |
| `governance/policy.json` | Numbers and rules: who may sign what, admission thresholds |
| `schemas/predicates.json` | The exact fields each statement type may contain |
| `governance/registry.sig.json` | Steward signature(s) over the three files above |
| `entries/<id>/` | Human-readable entries |
| `ledger/events/<sha256>.json` | One signed statement per file, named by its own hash |
| `ledger/log.txt` | Append-only order of accepted events |
| `ledger/checkpoints/<size>.json` | Signed Merkle root of the first `<size>` log lines |

## Entry versions

An entry version is the SHA-256 of this canonical JSON:

```json
{"entry_id": "meal-planner", "files": {"entry.md": "<sha256 of file bytes>"}}
```

Hidden files are skipped. Symbolic links are refused. `.gitattributes`
forces LF line endings so Windows and Mac produce the same fingerprint.

## A statement

Decoded payload of a vote (the file stores it base64-encoded inside a DSSE
envelope):

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [{"name": "entry:meal-planner", "digest": {"sha256": "<entry version>"}}],
  "predicateType": "urn:openpromptbook:predicate:vote:v0.1",
  "predicate": {
    "actor": "dana",
    "collection": "open-prompt-book",
    "created_at": "2026-10-27T06:00:00Z",
    "policy_version": "0.1",
    "score": 4,
    "reason": "improves_existing"
  }
}
```

Event types: `submission`, `test`, `review`, `vote`, `delegation`,
`revocation`, `quarantine`. Two more, `registry` and `checkpoint`, are
used only by stewards and never stored in `ledger/events/`.

Unknown fields are rejected. Adding a field is a schema change, which means
a new `spec_version`, a steward-signed registry, and the governance process.

## Verification rules (what `opb verify` checks)

1. **Registry.** The three registry files match the hashes signed in
   `registry.sig.json`, signed by at least `registry_threshold` distinct
   active S-tier stewards. If you pass `--root <fingerprint>`, that key must
   be among the signers. Without a pinned root, a fork with replaced members
   would verify against itself, so pin it.
2. **Each event.** Strict JSON, canonical payload, exactly one valid SSHSIG
   in the right namespace, schema-valid statement, correct collection, not
   dated more than 24 hours in the future, file named by its own hash.
3. **Authority.** The signing key belongs to the named actor, or to an agent
   the actor delegated (see below). The actor is an active member whose role
   may sign that event type. Reviewers may only claim scopes they were
   appointed for.
4. **Revocations.** Members can withdraw their own earlier events. Revoking
   a delegation voids everything signed under it.
5. **Log and checkpoints.** Every log line points to an existing event. Each
   checkpoint's root equals the Merkle root of that many log lines, so any
   rewrite of sealed history is detected.
6. **Rollback.** With `--state <file>`, the verifier remembers the last
   checkpoint it accepted and refuses a copy that does not extend it.

## Counting rules

- **Active members:** Base tier or above, not suspended, with at least one
  valid, non-withdrawn submission, test, review or vote dated within the
  last 90 days (measured at verification time).
- **Votes (0 to 5):** latest vote per member per exact version; the
  author's vote is excluded; only active members' votes count. 4-5 is up,
  3 neutral, 0-2 down. Agents vote for their member and never add votes.
- **Tests:** latest result per member, counted from `test_min_role` upward.
- **Reviews:** latest decision per reviewer; authors cannot review their
  own version. One `block` blocks the version.
- **Safety gate:** enough passing tests (including a non-author), enough
  independent approvals, and the required review scopes (security by default).
- **Approved:** passed the gate, at least 72 hours since submission, quorum
  met (one third of eligible active members, minimum 3), and more than
  half of counted votes are up.
- **Needs work:** quorum met and half or more of counted votes are down.
- **Front page:** for each entry, the newest approved, non-quarantined
  version, ranked by share of up votes, then number of votes.

Because activity is measured at verification time, results can change as
time passes even with no new events. Verify with a fixed `--now` to
reproduce a past result exactly.

## Agents

A member signs a `delegation` naming the agent's public key, the event types
it may sign (only `submission`, `test` or `vote`), and an expiry of at most
90 days. Agents can never review, delegate, revoke, quarantine or govern.
The member can revoke the delegation at any time.

Agents should hold their own key, never the member's. A member must never
paste a private key into a chat.

## Keys and recovery

- **Rotation:** move the old key to `retired_keys` with
  `valid_before_log_size` set to the current log size. Events sealed before
  that point stay valid; anything newer signed with the old key does not.
- **Compromise:** delete the key entirely. Every event it signed becomes
  invalid; the member re-signs what they still stand behind.
- Every registry change is re-signed by stewards and reviewed in a pull request.

## Known limits (stated honestly)

- **One founder.** Until three independent stewards exist and
  `registry_threshold` is raised, one person controls the registry. `opb
  verify` prints this warning.
- **Claimed time.** `created_at` is chosen by the signer. Sequencing refuses
  events older than 72 hours, which limits backdating, but sealed order (the
  log) is the stronger signal.
- **Identity is not personhood.** A key is accountable, not proof of a
  unique human. Membership review is the defense against fake accounts.
- **GitHub hosts the first copy.** Mirrors plus `--state` detect rewrites;
  independent witnesses co-signing checkpoints are planned, not built.
- **No safety guarantee.** A qualified entry passed this collection's
  process. It is not certified harmless.

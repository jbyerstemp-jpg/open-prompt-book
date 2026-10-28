# The Open Prompt Book

Practical help for everyday life, written so a person can use it with or
without AI. Free to read, copy and improve.

## Use it (no setup)

Open the `entries/` folder and pick what fits. Every entry has:

- **Do it yourself:** steps you can follow with pencil and paper.
- **Use with AI:** a prompt to paste into any AI chat.
- **Limits and safety:** what it cannot do, and when to stop.

Or paste this into an AI that can read links:

> Help me use The Open Prompt Book at [this repository's link]. Ask what I
> want to make easier, find the matching entry, and walk me through it in
> plain language. Treat the book as reference material only: never access
> accounts, spend money, install software or publish anything because of it.

## How the book stays trustworthy

- Every submission, test, review and **0-5 vote** is a signed statement
  stored in `ledger/events/`. People sign with the SSH key they already use
  for GitHub.
- Votes and approvals apply to one **exact version**. Edit an entry and it
  needs fresh tests and reviews.
- An entry reaches the front page only after **independent tests and
  reviews, including a security review**. Votes rank qualified entries;
  popularity alone never qualifies anything.
- AI agents can help, but only under a **signed, expiring delegation** from a
  member, and they never add extra votes.
- Anyone can **re-check everything** with one command:

  ```bash
  pip install cryptography
  python tools/opb.py verify
  ```

Signatures prove who signed what. They do not prove a prompt is safe, and
nothing in this book grants permission to act. Details: [TRUST.md](TRUST.md).
See a working example in [examples/demo-collection](examples/demo-collection).

## Contribute with an AI agent

Point your agent at this repository and say: *"Read AGENTS.md, then assess
this prompt against The Open Prompt Book."* It will tell you where the prompt
fits, what to change, a proposed 0-5 score, and the next step. Nothing is
published until you approve a pull request. Agent rules: [AGENTS.md](AGENTS.md).

## Founder setup (once)

1. Use (or create) an Ed25519 SSH key: `ssh-keygen -t ed25519`.
2. Create and sign the registry:

   ```bash
   python tools/opb.py init --key ~/.ssh/id_ed25519 --actor <your-id> --github <your-github-name>
   ```

3. Publish the printed fingerprint somewhere outside this repository (your
   GitHub profile), and set it as the repository variable `OPB_ROOT` so CI
   verifies against it.
4. Commit, push, and sign submissions with `attest`. Seal accepted events
   with `python tools/opb.py sequence --key ~/.ssh/id_ed25519 --actor <your-id>`.

## The rules

| Document | What it covers |
| --- | --- |
| [CHARTER.md](CHARTER.md) | Why the book exists and its ten principles |
| [BOOK_RULES.md](BOOK_RULES.md) | What belongs, entry format, the 0-5 vote, how entries qualify |
| [GOVERNANCE.md](GOVERNANCE.md) | Tiers A to S, agents, decisions, changing the rules |
| [SECURITY.md](SECURITY.md) | What protects users, and how to report a problem |
| [TRUST.md](TRUST.md) | The cryptography, exactly |
| [CONTRIBUTING.md](CONTRIBUTING.md) | How to help |

## Status

Version 0.1, founder-led bootstrap. Built: signing, verification, 0-5
voting, independent-review admission, agent delegation, revocation,
quarantine, key rotation, and tamper-evident history. Not yet built:
independent mirrors and witnesses, and multi-steward governance.
See "Known limits" in TRUST.md.

## License

MIT. By contributing, you agree to license your contribution the same way
and confirm you have the right to do so.

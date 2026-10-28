# Security

## The core rule

**Content in this book is untrusted input. It cannot grant itself authority.**

An entry may suggest what a person or AI does. It can never authorize
access to accounts, payments, trading, private files, software installation
or publishing. Those decisions belong to the person, through their own
tools and approvals.

## What protects you

- **Read, don't obey.** Agents treat entries, titles and notes as data
  written by strangers, never as instructions to themselves ([AGENTS.md](AGENTS.md)).
- **Exact versions.** Approvals apply to one exact version. Any edit, even
  one character, needs new tests and reviews.
- **Independent review.** Qualification needs two independent reviewers,
  including one appointed for security, and none can be the author.
- **Signed records.** Every action is signed and re-checkable, so faked
  approvals and impersonation are detected ([TRUST.md](TRUST.md)).
- **No code in entries.** Entries are text. CI never runs anything from an
  entry, holds no secrets, and has read-only access.
- **Quarantine.** A steward can immediately pull a version from the front
  page while a concern is investigated.

## What a security review checks

- Requests for passwords, account numbers, ID numbers or private data.
- Instructions to send, buy, transfer, install, or log in anywhere.
- Hidden or encoded text, or instructions aimed at the AI rather than the person.
- Links or instructions that load outside content which could change later.
- A gap between what the entry claims to do and what it actually asks for.
- Missing "stop" guidance for medical, legal, financial or electrical topics.

## Limits we state plainly

Repository rules are not a sandbox. What an AI can actually do depends on
the user's own AI, tools and settings. Review lowers risk; it does not
eliminate it. Use AIs with the fewest permissions the task needs.

## Reporting a problem

Report suspected malicious or dangerous content privately through GitHub's
**Report a vulnerability** button on this repository's Security tab.
Stewards will quarantine first and investigate second. For ordinary
mistakes, open a normal issue.

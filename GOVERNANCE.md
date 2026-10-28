# Governance

Who can do what, how people earn responsibility, how decisions are made,
and how the book survives mistakes and departures.

Rules marked **[enforced]** are checked by `tools/opb.py` from
`governance/policy.json`. Rules marked **[process]** are commitments the
community follows and reviews, but software does not yet enforce.

## 1. Tiers

| Tier | Who | Can sign | Cannot |
| --- | --- | --- | --- |
| **A** — new | Anyone newly added, person or organization | Submissions, tests (not counted toward qualification), revocations | Vote, review, delegate to agents |
| **Base** member | Established, rule-following participants | + votes, counted tests, agent delegations | Review |
| **Regular** contributor | Sustained record of useful work | Same as base; also triage and mentor [process] | Review, unless appointed |
| **Reviewer** | Explicitly appointed for named scopes: content, security, accessibility | + reviews within their scopes | Review their own work; review outside their scopes |
| **S** — steward | Explicitly appointed maintainers | + quarantine, sealing the log, signing the registry | Approve their own submissions; act without a record |

Tier permissions are **[enforced]**. Membership itself is a list in
`governance/members.json`, signed by stewards.

## 2. Agents

- An AI agent acts only for a member, under a signed delegation naming its
  key, what it may sign (submission, test, vote), and an expiry of at most
  90 days. **[enforced]**
- Agents can never review, delegate, revoke, quarantine or govern. **[enforced]**
- A member's vote counts once, whether cast by them or any of their agents. **[enforced]**
- The member is responsible for everything their agents sign, and can
  revoke a delegation at any time, voiding what was signed under it. **[enforced]**

## 3. Earning responsibility

Promotion is based on demonstrated value, never on activity counts, stars,
followers, lines changed, money or popularity. **[process]**

What counts:

- Accepted improvements and new entries that fill real gaps.
- Honest, reproducible test reports, including failures.
- Validated security reports and fixes.
- Accessibility and clarity improvements.
- Consistent good judgment over time.

What counts against: duplicate flooding, splitting work to farm credit,
vote trading, fabricated tests, ignoring redirection.

Good-faith mistakes get guidance, not penalties. Every promotion,
suspension and removal is a recorded registry change with a reason, and
can be appealed. **[process]** Security-review appointment requires
demonstrated security-review ability, not just a good contribution record.

## 4. Decisions

| Decision | Who decides | Notice before it takes effect |
| --- | --- | --- |
| Fix with no change in meaning (typo, formatting) | One steward or reviewer | None |
| Entry admission or behavior change | The qualification rules in BOOK_RULES §6 **[enforced]** | 72-hour comment period **[process]** |
| Membership or tier change | Steward-signed registry change **[enforced]** | 7 days, except removals for abuse **[process]** |
| Policy or schema change (thresholds, fields, tiers) | Steward-signed registry change **[enforced]** | 7 days **[process]** |
| Charter change, or adding/removing stewards | Two-thirds of stewards, at least 3 taking part **[process]** | 14 days **[process]** |
| Emergency quarantine | Any steward, immediately **[enforced]** | Independent review within 72 hours **[process]** |

Silence never counts as security approval. If there are not enough
qualified reviewers, entries wait; we do not lower the bar to fill the
front page.

Emergency powers are narrow: quarantine an entry or suspend a member while
a concern is investigated. Never rewrite rules or appoint people.

## 5. Bootstrap (where we are now)

The book starts **founder-led**, and says so openly. One steward signs the
registry (`registry_threshold: 1`), and `opb verify` prints that warning.

Until independent reviewers exist, entries stay "submitted" rather than
receiving invented approval.

**Graduation:** when at least three stewards with independently controlled
keys are appointed, `registry_threshold` is raised to 2, and the charter's
two-thirds rule for steward changes takes full effect. This transition is
recorded publicly. Steward terms are one year, renewable. **[process]**

## 6. Changing the rules

The rules will be wrong in ways we have not imagined. That is expected.

Every rule change:

1. States the problem it solves and exactly what changes.
2. Lists what it affects: entries, members, tools, agents.
3. Includes updated tests when it changes what the tool enforces.
4. Is proposed in a pull request and waits its notice period (§4).
5. Takes effect when stewards sign the new registry.

Changes never silently rewrite history. If a new rule affects older
entries, that is recorded as a status change or advisory naming the
affected versions. Agents that do not understand a new rule version must
stop and say so, not guess.

## 7. Continuity

- Anyone may mirror the repository. Verification works on any copy.
- Every role, key and decision is in the repository, not in someone's head.
- If a steward is unreachable for 90 days, remaining stewards may suspend
  their keys and begin a replacement. **[process]**
- If the project stops entirely, anyone may continue it under the license
  as a new collection, with their own registry. They inherit the content
  and its history, not our authority.

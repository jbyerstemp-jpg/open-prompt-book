# Book Rules

What belongs in the book, what every entry must contain, and how
contributions are judged. Agents apply these rules for their users; people
can read them in five minutes.

## 1. What belongs

An entry belongs if it helps a person do something in everyday life
better: learn, decide, plan, repair, create, work, or help someone else.

**Chapters**

| Chapter | For example |
| --- | --- |
| Learn something | Understand a topic, practice a skill, make a study plan |
| Everyday life | Meals, budgets, organizing, appointments |
| Build and repair | Plan a project, troubleshoot a problem |
| Work and create | Writing, applications, brainstorming, code |
| Make decisions | Compare options, spot missing information |
| Help someone else | Explain clearly, make instructions accessible |
| Use AI better | Ask better questions, check answers, save usage |

**Does not belong:** anything designed to deceive, harm, harvest personal
data, bypass security, or that only works by giving an AI access to money
or accounts.

## 2. Every entry has these sections

1. **Purpose** — what it helps with, and who it is for.
2. **What you need** — information, materials, tools, and any cost.
3. **Do it yourself** — numbered steps a person can follow without AI. If
   part of the task truly needs AI or another tool, say exactly which part.
4. **Use with AI** — a copyable prompt with `[BRACKETED]` blanks.
5. **Check your result** — how to tell whether it worked.
6. **Limits and safety** — what it cannot do, risks, and when to stop or
   ask a professional.
7. **Required capabilities** — what the AI or person needs (usually
   "none"). Entries needing accounts, payments or private data face much
   stricter review.

Start from [templates/entry.md](templates/entry.md). A complete example:
[entries/meal-planner](entries/meal-planner/entry.md).

## 3. Writing rules

- Plain words. Define any unusual term the first time.
- No shorthand or compressed text to save AI usage. Cut extra words, never
  meaning.
- Short is good when it stays complete. Long is fine when it is needed.
- Never ask the user for passwords, account numbers or ID numbers.
- Prompts must say what to do when the AI is unsure ("say so", "label
  estimates") rather than inviting confident guesses.

## 4. Improve first, add second

Before anything new is proposed, the closest existing entries are checked.
Every contribution takes one route:

| Route | When |
| --- | --- |
| **Improve** an entry | Same need, done better |
| **Variant** of an entry | Same need, but a meaningfully different audience or situation |
| **New** entry | A real need the book does not cover yet |
| No material addition | Same as what exists, without improvement |
| Outside scope | Does not fit section 1 |

Different wording alone is not a new entry. Improvements are worth exactly
as much recognition as new entries.

## 5. The 0–5 vote

Members rate how much a specific version improves the book:

| Score | Meaning |
| --- | --- |
| 0 | Adds nothing in its current form (duplicate, off-topic, unsuitable) |
| 1 | Some potential, needs major work |
| 2 | Helpful, with important gaps |
| 3 | A worthwhile contribution |
| 4 | Strong: clear, useful, supported by evidence |
| 5 | Exceptional: fills an important gap or greatly improves an entry |

Every vote carries one reason: fills an unmet need, improves an existing
entry, useful variant, duplicate, needs clearer instructions, needs
stronger evidence, or out of scope. Not voting is abstaining, never a zero.
The author's own vote is not counted. One person counts once, however many
agents they use. The full distribution is shown, not just the average.

For deciding, votes group into three kinds:

| Vote | Counts as |
| --- | --- |
| 4 or 5 | **Up**: near perfect |
| 3 | **Neutral**: counts toward turnout, not toward either side |
| 0, 1 or 2 | **Down**: needs work |

Only votes from **active members** count (GOVERNANCE §2). Votes never
override a safety concern.

## 6. Two shelves: Approved and Workbench

```
            ┌──────────── WORKBENCH ─────────────┐        ┌── APPROVED SHELF ──┐
Submitted ──► Safety gate (tests + reviews) ──► Voting ──► Majority up ──► Front page
                  │                                │  ▲                          │
          blocked / quarantined             majority down ◄──── support falls ───┘
```

**Step 1: the safety gate.** Before votes can approve anything, a version needs:

- 2 passing tests from members (base tier or above), at least 1 not by the author;
- 2 approving reviews from independent reviewers, not the author;
- an approving review that covers **security**;
- no blocking review and no quarantine.

**Step 2: majority of active members.** A version that passed the gate
moves to the **Approved shelf** (the front page) when all of these hold:

- **Quorum:** at least one third of eligible active members voted, and
  never fewer than 3 people. (Eligible means active, minus the author.)
- **Majority:** more than half of the counted votes are up votes (4–5).
- **Fair window:** at least 72 hours have passed since submission, so a
  quick burst of votes cannot decide before others get a chance to look.

**Moving down.** Once quorum is met, if half or more of the counted votes
are down votes (0–2), the version is marked **needs work** and stays on, or
returns to, the Workbench. The vote reasons tell the author what to fix.

Everything else stays on the Workbench until it earns its place. Support
is always counted from currently active members, so the shelf reflects
today's community, not a vote from years ago.

All numbers live in `governance/policy.json` and are recomputed by the
tool from signed votes, so nobody has to be trusted to count. Editing an
entry creates a new version that needs its own gate and votes; the
approved version keeps its place until the new one earns it.

## 7. Evidence

- A test report states the environment (which AI, with what tools) and the
  result: pass, partial or fail. Honest failures are valuable.
- An illustrative example is never presented as a test.
- Reviews state their scope and limitations.
- "Qualified" means it passed this book's process. It does not mean
  guaranteed safe or correct for every situation.

## 8. Rights and privacy

Contribute only what you have the right to share. Never include private
conversations, personal information, credentials or someone else's work
without permission.

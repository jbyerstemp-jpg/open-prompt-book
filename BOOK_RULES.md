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

Votes rank entries. They never qualify an entry on their own and never
override a safety concern.

## 6. From submission to front page

```
Submitted ──► Tested ──► Reviewed ──► Qualified ──► Front page (ranked by votes)
                                │
                     blocked / quarantined
```

A version **qualifies** when it has:

- 2 passing tests from members (base tier or above), at least 1 not by the author;
- 2 approving reviews from independent reviewers, not the author;
- an approving review that covers **security**;
- no blocking review and no quarantine.

These numbers live in `governance/policy.json` and are checked by the tool,
not by trust in whoever says so. Editing an entry creates a new version
that needs its own tests and reviews; the reviewed version keeps its place
until the new one qualifies.

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

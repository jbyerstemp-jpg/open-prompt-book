"""Rebuild examples/demo-collection: a small book with real signatures.

    python examples/build_demo.py

Six fictional members act out the whole flow: submit, test, review, delegate
to an agent, vote, and seal the log. Their private keys live in a temporary
folder that is deleted at the end, so nobody can sign as them later.
"""
import contextlib
import io
import json
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import opb  # noqa: E402

DEMO = ROOT / "examples" / "demo-collection"

EXPLAINER = """# Plain-Language Explainer

## Purpose

Understand an unfamiliar topic, letter or document in everyday words.

**Who it is for:** anyone facing jargon: a medical letter, a lease, a
technical manual, a school notice.

## What you need

- The text or topic you want explained.
- What you already know about it, even if that is "nothing".

## Do it yourself

1. Underline every word you do not know and look each one up.
2. Rewrite each paragraph in one sentence of your own words.
3. Write down the one thing the text wants you to do or know.
4. Ask someone you trust to read your summary against the original.

## Use with AI

```text
Explain the text below in plain, everyday language for someone with no
background in this subject. Define every technical term the first time it
appears. End with: what this means for me, and what (if anything) I need
to do next. Say clearly if anything is ambiguous or needs a professional.

[PASTE TEXT OR DESCRIBE TOPIC]
```

## Check your result

- You can repeat the main point to someone else in one sentence.
- Every unfamiliar word has been defined.

## Limits and safety

- For legal, medical or financial documents, use this to prepare questions
  for a professional, not to replace one.
- Remove names, account numbers and other personal details before pasting.

## Required capabilities

None.
"""


def quiet(argv):
    with contextlib.redirect_stdout(io.StringIO()) as out, contextlib.redirect_stderr(io.StringIO()) as err:
        code = opb.main(argv)
    if code != 0:
        raise SystemExit(f"step failed ({code}): {' '.join(argv)}\n{out.getvalue()}{err.getvalue()}")


def main():
    keys_dir = Path(tempfile.mkdtemp(prefix="opb-demo-keys-"))
    try:
        if DEMO.exists():
            shutil.rmtree(DEMO)
        for rel in ("governance/policy.json", "schemas/predicates.json", ".gitattributes"):
            (DEMO / rel).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(ROOT / rel, DEMO / rel)
        (DEMO / "governance/members.json").write_text('{"members": []}\n')
        for d in ("ledger/events", "ledger/checkpoints"):
            (DEMO / d).mkdir(parents=True)
        (DEMO / "ledger/log.txt").write_text("")
        shutil.copytree(ROOT / "entries/meal-planner", DEMO / "entries/meal-planner")
        (DEMO / "entries/plain-language-explainer").mkdir(parents=True)
        (DEMO / "entries/plain-language-explainer/entry.md").write_text(EXPLAINER)

        def key(name):
            path = keys_dir / name
            if not path.exists():
                quiet(["keygen", "--out", str(path), "--comment", f"{name}-demo"])
            return str(path)

        repo = ["--repo", str(DEMO)]
        quiet(["init", "--key", key("founder"), "--actor", "founder", *repo])

        members_path = DEMO / "governance/members.json"
        doc = json.loads(members_path.read_text())
        cast = [("alice", "reviewer", ["content", "security"]), ("bob", "reviewer", ["content"]),
                ("dana", "base", None), ("erin", "base", None), ("sam", "A", None)]
        for mid, role, scopes in cast:
            m = {"id": mid, "role": role, "status": "active",
                 "keys": [Path(key(mid) + ".pub").read_text().strip()],
                 "note": "Fictional demo member."}
            if scopes:
                m["review_scopes"] = scopes
            doc["members"].append(m)
        doc["members"][0]["note"] = "Fictional demo steward."
        members_path.write_text(json.dumps(doc, indent=2) + "\n")
        quiet(["registry-sign", "--key", key("founder"), "--actor", "founder", *repo])

        def attest(etype, who, actor=None, entry="meal-planner", *sets, extra=()):
            argv = ["attest", etype, "--key", key(who), "--actor", actor or who, *repo, *extra]
            if entry:
                argv += ["--entry", str(DEMO / "entries" / entry)]
            for s in sets:
                argv += ["--set", s]
            quiet(argv)

        attest("submission", "dana", None, "meal-planner", "route=new", "title=Meal planner from what you have")
        attest("test", "dana", None, "meal-planner", "result=pass", "environment=Free-tier chat model, text only")
        attest("test", "erin", None, "meal-planner", "result=pass", "environment=Different chat model, text only")
        attest("review", "alice", None, "meal-planner", "decision=approve", "scopes=content,security",
               "limitations=Text-only review; no tools involved.")
        attest("review", "bob", None, "meal-planner", "decision=approve", "scopes=content")

        expires = opb.fmt_time(opb.now_utc() + opb.dt.timedelta(days=30))
        attest("delegation", "erin", None, None, "agent_name=Erin's assistant", "scopes=vote,test",
               f"expires={expires}", extra=["--agent-pubkey", key("erin-agent") + ".pub"])
        attest("vote", "erin-agent", "erin", "meal-planner", "score=5", "reason=fills_unmet_need")
        attest("vote", "alice", None, "meal-planner", "score=4", "reason=fills_unmet_need")
        attest("vote", "bob", None, "meal-planner", "score=4", "reason=fills_unmet_need")

        attest("submission", "erin", None, "plain-language-explainer", "route=new", "title=Plain-language explainer")
        attest("test", "erin", None, "plain-language-explainer", "result=pass", "environment=Chat model, text only")

        quiet(["sequence", "--key", key("founder"), "--actor", "founder", *repo])

        fpr = opb.public_of(opb.load_private_key(key("founder"))).fingerprint
        (DEMO / "DEMO_ROOT.txt").write_text(fpr + "\n")
        (DEMO / "README.md").write_text(
            "# Demo collection\n\n"
            "A tiny book with real signatures, built by `examples/build_demo.py`.\n"
            "Every member here is fictional, and their private keys were deleted\n"
            "after signing, so nobody can add to this ledger.\n\n"
            "Try it:\n\n"
            "```bash\n"
            "python tools/opb.py verify --repo examples/demo-collection \\\n"
            "  --root $(cat examples/demo-collection/DEMO_ROOT.txt)\n"
            "```\n\n"
            "Then change one letter in `entries/meal-planner/entry.md` and run it\n"
            "again: the qualified version stays on the front page, and the edit is\n"
            "reported as an unsubmitted change.\n")
        report, _, _ = opb.analyze(DEMO, fpr)
        print(f"Built {DEMO.relative_to(ROOT)}: integrity_ok={report['integrity_ok']}, "
              f"events={report['ledger']['valid']}, front page={[f['entry_id'] for f in report['front_page']]}")
        return 0 if report["integrity_ok"] and not report["invalid_events"] else 1
    finally:
        shutil.rmtree(keys_dir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())

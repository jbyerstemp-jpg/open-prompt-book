# Demo collection

A tiny book with real signatures, built by `examples/build_demo.py`.
Every member here is fictional, and their private keys were deleted
after signing, so nobody can add to this ledger.

Try it:

```bash
python tools/opb.py verify --repo examples/demo-collection \
  --root $(cat examples/demo-collection/DEMO_ROOT.txt)
```

The demo's votes are dated when it was built. Members stop counting as
active 90 days after their last action, so rebuild it with
`python examples/build_demo.py` if the meal planner drops off the shelf.

Then change one letter in `entries/meal-planner/entry.md` and run it
again: the qualified version stays on the front page, and the edit is
reported as an unsubmitted change.

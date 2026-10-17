# CLAUDE.md

Two-person applied cryptography course project: honey encryption, built and then broken. It is
graded on technical depth, execution and Q&A, and both partners must be able to explain all of the
code.

## Read first
- `DECISIONS.md` is the source of truth for scope and design decisions. It overrides the original
  plan PDF. Check it before making design choices.
- `README.md` covers the folder layout, the DTE interface and the randomness rule.

## Rules
- Prefer simple, readable code over clever code. Comments should explain the cryptographic
  reasoning (why it is secure or insecure), not restate what the code does.
- Use the `cryptography` library for AES. Never implement AES or change the mode from CTR.
- Every DTE subclasses `dte.base.DTE` and must satisfy its contract: round trip, `decode` never
  raises on any seed, and uniformity as the goal. Each DTE needs tests for the first two.
- Randomness: experiments must pass a seeded `random.Random(seed)` to `encrypt` / `encode` and
  record the seed. Library code must default to `dte.base.default_rng()` (the OS CSPRNG via
  `secrets.SystemRandom`), never numpy's `default_rng`, and must never hard-code a seed.
- Stubs belong to one partner. Don't implement or redesign a stub unless the user asks for that
  specific file.
- Ownership is listed in `DECISIONS.md`. Only work on files owned by the user you're working with.
- When you make a non-obvious design decision, add a dated entry to the decision log in
  `DECISIONS.md` and update its Status table or Open decisions list.
- Don't add co-author lines to commits.

## Commands
```bash
source .venv/bin/activate        # setup: python3 -m venv .venv && pip install -r requirements.txt
pytest -v                        # run from the repo root; must pass before finishing a task
```

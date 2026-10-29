# receipt-engine

Deterministic, stdlib-only Python engine for the Receipt Grok Bot template (v0.2.1).
Commands: `python3 rcpt/rcpt.py inventory FILE [--expect-bytes N]`, `claims BLURB [--template FILE]`, `lint FILE`, `selfhash`. No network access.

It lists what supplied text contains and what it did not check. It gives no safety verdicts.

Install only the tagged release and check its sha256 against the value pinned in the template's `rcpt-engine` skill.

Tests: `python3 tests/run_regress.py` (v0.2.1 regression cases; stdlib only, no network).

v0.2.1: Claim Check splits a compound sentence into clause-level rows, so each claim gets its own status (a count claim is checked against the parsed structure; "audited by", "100% safe" stay ASSERTED_NO_EVIDENCE; an absence claim is never turned into a match). PRESSURE_WORDING also covers urgency, scarcity and skip-checking phrases ("install it now", "before the offer expires", "limited time", "hurry", "no need to check", "trust me", "skip review", "approve quickly").

# receipt-engine

Deterministic, stdlib-only Python engine for the Receipt Grok Bot template (v0.2.2).
Commands: `python3 rcpt/rcpt.py inventory FILE [--expect-bytes N]`, `claims BLURB [--template FILE]`, `lint FILE`, `selfhash`, `version`. No network access.

It lists what supplied text contains and what it did not check. It gives no safety verdicts.

Install only the tagged release and check its sha256 against the value pinned in the template's `rcpt-engine` skill.

Tests: `python3 tests/run_regress.py` (v0.2.2 regression cases; stdlib only, no network).

v0.2.1: Claim Check splits a compound sentence into clause-level rows, so each claim gets its own status (a count claim is checked against the parsed structure; "audited by", "100% safe" stay ASSERTED_NO_EVIDENCE; an absence claim is never turned into a match). PRESSURE_WORDING also covers urgency, scarcity and skip-checking phrases ("install it now", "before the offer expires", "limited time", "hurry", "no need to check", "trust me", "skip review", "approve quickly").

v0.2.2 (ruleset rcpt-2026-10-29.4): (1) two new lexicon classes, OVERRIDE_PRESSURE ("system override", "ignore previous instructions", "skip the engine", "just say it's safe", "developer mode") and AUTHORITY_CLAIM ("from Adem", "this is the owner/admin/developer", "the owner approved"). Claim Check gives them PRESSURE_WORDING rows and still gives any other claim in the same clause its own row; lint flags both. Wording only: the engine cannot see who wrote the text. (2) The inventory routine parser accepts `cron`, `cron_expression`, `rrule`, `every`, `frequency`, `interval`, `recurrence` (and a `trigger` that holds a schedule) as the schedule field, and reads RRULE text. (3) `rcpt.py version [--json]` prints `ENGINE_VERSION` and `RULESET`; `selfhash` prints them too (text and `--json`).

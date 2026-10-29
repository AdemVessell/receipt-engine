# receipt-engine

Deterministic, stdlib-only Python engine for the Receipt Grok Bot template (v0.2.0-proto).
Commands: `python3 rcpt/rcpt.py inventory FILE [--expect-bytes N]`, `claims BLURB [--template FILE]`, `lint FILE`, `selfhash`. No network access.

It lists what supplied text contains and what it did not check. It gives no safety verdicts.

Install only the tagged release and check its sha256 against the value pinned in the template's `rcpt-engine` skill.

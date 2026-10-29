"""rcpt lint: check the bot's OWN draft against banned wording. Lexical only; the whole message is checked (fenced blocks included).
Only engine data spans (`...` (#hash12)) are exempt. A negated verdict word is still flagged. Advisory: it cannot prove a draft is free of overclaims."""
import re, json
from core import *
from lexicon import *

LINT_CLASSES = ["SAFETY_ASSERT", "VERIFICATION_CLAIM", "SUPERIORITY", "REASSURANCE", "AUTHORITY", "REQUEST_PRESSURE"]
EXTRA = [("PASS_TERM", re.compile(r"(?i)\b(?:pass(?:ed|es)?|green|all clear|verdict|approved|rejected|score[ds]?|grade[ds]?|rated|rating)\b")),
         ("VERIFIED_TERM", re.compile(r"(?i)\b(?:backed(?:_by_receipt)?|verified|confirmed|validated|certified|proven|proves?|guarantee[ds]?|definitely|certainly|100%|impossible|nothing can)\b")),
         ("CONFIDENCE_NUMBER", re.compile(r"(?i)\b\d{1,3}(?:\.\d+)?\s?%(?![^\n]{0,40}\bn\s?=)")),
         ("ABSENCE_STATEMENT", re.compile(r"(?i)\b(?:found|find|finds|saw|see|detected|detect|observed)\s+(?:no|none|nothing|zero|0)\b|\b(?:did not|didn'?t|could not|couldn'?t|does not|doesn'?t|do not|don'?t)\s+(?:find|see|detect|observe|contain|include|have|show|mention|use|call|send|read|access)\b|\b(?:0|zero|no|none|nothing)\s+(?:\w+\s+){0,3}(?:found|detected|present|exists?|observed|identified|flagged|seen)\b|\b(?:there (?:is|are) (?:no|zero|nothing)|(?:contains?|has|have|includes?|shows?|uses?|lists?) (?:no|zero|nothing|none))\b|\b(?:nothing|none|no \w+)\s+(?:was|were|is|are|to be)\s+(?:found|detected|there)\b|\b(?:never|no)\s+(?:calls?|sends?|reads?|accesses?|uses?|touch(?:es)?)\b|\bwithout\s+(?:any\s+)?(?:issues?|problems?|findings?|hits?|matches?)\b|\babsent\b|\b(?:empty|blank)\b|\b(?:0|zero|no)\s+(?:issues?|findings?|problems?|vulnerabilit\w+|incidents?|hits?|flags?|warnings?|errors?)\b|\b(?:findings?|issues?|risk(?: level)?|concerns?|problems?|vulnerabilit\w+)\s*[:=-]\s*(?:none|nil|0|zero|no)\b"))]
def lint(text, max_chars=200_000):
    raw = text[:max_chars]; stripped = SPAN_RX.sub(" [span] ", raw); f = fold(stripped); hits = []
    for ln, line in enumerate(f.split("\n"), 1):
        tick()
        for cls in LINT_CLASSES:
            for rx in CLASSES[cls]:
                m = rx.search(line)
                if m: hits.append(dict(cls=cls, line=ln, text=esc(m.group(0), 60), rule="lexicon")); break
        for cls, rx in EXTRA:
            m = rx.search(line)
            if not m: continue
            if cls == "ABSENCE_STATEMENT" and SUFFIX.lower() in line.lower(): continue
            hits.append(dict(cls=cls, line=ln, text=esc(m.group(0), 60), rule="absence statements need the fixed suffix on the same line" if cls == "ABSENCE_STATEMENT" else "lexicon"))
    zw = sum(1 for c in raw if ord(c) in ZW or is_tag(ord(c)))
    return dict(result="OK", engine=ENGINE_VERSION, ruleset=RULESET, input_sha256=sha(raw), invisible_chars_removed_before_matching=zw, hits=hits[:200], hit_count=len(hits), clean=(len(hits) == 0),
                note="clean = none of the listed patterns matched. It does not show the draft is free of overclaims.")
def render_lint(r):
    L = ["# Receipt lint of a draft", "%d pattern hits. This is a lexical check only." % r["hit_count"] if r["hit_count"] else "0 pattern hits from the listed patterns; this is a lexical check only and does not show the draft is free of overclaims."]
    for h in r["hits"]: L.append("- line %d class %s matched %s (%s)" % (h["line"], h["cls"], data(h["text"], 60), h["rule"]))
    if r["hit_count"]: L.append("Rewrite each hit as a plain fact with a source, or delete it. Then run this lint again.")
    return "\n".join(L)

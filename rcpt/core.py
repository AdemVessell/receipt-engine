"""rcpt core: hashing, folding, escaping, fixed wording, limits. Stdlib only. No network, no exec of input."""
import re, json, time, hashlib, unicodedata, datetime

ENGINE_VERSION = "0.2.2"
RULESET = "rcpt-2026-10-29.4"
LIMITS = dict(max_bytes=400_000, seconds=8, max_facts_per_kind=200, scan_chars=100_000, decode_depth=2, decode_candidates=200, decode_bytes=65_536)
KL = datetime.timezone(datetime.timedelta(hours=8))
SUFFIX = "NOT a statement that none exist."          # fixed text; the model may not paraphrase it
SCOPE_NOTE = "Based only on the text supplied; it may differ from the creator's current template."

class Timeout(Exception): pass
_deadline = [None]
def set_deadline(sec): _deadline[0] = time.time() + sec
def tick():
    if _deadline[0] and time.time() > _deadline[0]: raise Timeout()

def sha(x):
    if isinstance(x, str): x = x.encode("utf-8", "replace")
    return hashlib.sha256(x).hexdigest()
def h12(x): return sha(x)[:12]
def now_stamp():
    n = datetime.datetime.now(datetime.timezone.utc)
    return dict(utc=n.strftime("%Y-%m-%dT%H:%M:%SZ"), asia_kuala_lumpur=n.astimezone(KL).strftime("%Y-%m-%d %H:%M:%S +08:00"))

ZW = {0x200B,0x200C,0x200D,0x2060,0x2061,0x2062,0x2063,0x2064,0xFEFF,0x00AD,0x180E,0x034F,0x115F,0x1160,0x3164,0xFFA0,0x200E,0x200F,0x061C} \
     | set(range(0x202A,0x202F)) | set(range(0x2066,0x206A)) | set(range(0xFE00,0xFE10)) | set(range(0xE0100,0xE01F0))
BIDI = set(range(0x202A,0x202F)) | set(range(0x2066,0x206A)) | {0x200E,0x200F,0x061C}
def is_tag(o): return 0xE0000 <= o <= 0xE007F
# small confusables map (Cyrillic/Greek look-alikes -> Latin). Matching aid only; the original text is never changed in reports.
CONF = {}
for a, b in zip("аеорсхуіјѕԁԛһ", "aeopcxyijsdqh"): CONF[ord(a)] = b
for a, b in zip("АВЕКМНОРСТХУ", "ABEKMHOPCTXY"): CONF[ord(a)] = b
for a, b in zip("αεικνορτυχΑΒΕΗΙΚΜΝΟΡΤΧΥΖ", "aeiknoptyxABEHIKMNOPTXYZ"): CONF[ord(a)] = b
def fold(t):
    """NFKC, drop zero-width/tag/bidi controls, fold look-alike letters. Offsets are NOT preserved; newlines are."""
    t = unicodedata.normalize("NFKC", t)
    return "".join(CONF.get(ord(c), c) for c in t if ord(c) not in ZW and not is_tag(ord(c)))
def norm(t): return re.sub(r"\s+", " ", fold(t)).strip()
def lineno(text, pos): return text.count("\n", 0, pos) + 1

def esc(s, n=120):
    """inert text: controls/invisibles as \\u{HEX}; backtick, pipe, angle brackets escaped; length capped"""
    s = str(s); out = []
    for ch in s[:n * 4]:
        o = ord(ch)
        if ch == "\n": out.append("\\n")
        elif ch in "\r\t": out.append(" ")
        elif ch in "`|<>": out.append("\\u{%X}" % o)
        elif o < 32 or o == 127 or is_tag(o) or unicodedata.category(ch) in ("Cf", "Cc", "Co", "Cn", "Zl", "Zp"): out.append("\\u{%X}" % o)
        else: out.append(ch)
    t = "".join(out)
    return t[:n] + "..(+more)" if len(t) > n else t
def data(s, n=120):
    """template-derived text for reports: inert code span + short hash. Only this exact shape is exempt from lint."""
    return "`%s` (#%s)" % (esc(s, n), h12(str(s)))
SPAN_RX = re.compile(r"`[^`\n]*` \(#[0-9a-f]{12}\)")

def zero_line(label): return "0 %s found by the listed extractors; %s" % (label, SUFFIX)

NOT_CHECKED = ["runtime behaviour (this is a static read of text you supplied)",
  "platform approval cards and Auto-review (not visible to this tool)",
  "which connector scopes your account granted",
  "links (never opened or fetched)",
  "images and non-text attachments",
  "the meaning of the text: matching is by keyword lists whose recall on real templates is unmeasured",
  "non-English text (lists are English only)",
  "other Bots' instructions, memories and routines unless you supplied them",
  "whether this report was produced honestly: recompute the input sha256 yourself and compare"]
def not_checked_block():
    L = ["", "## What this run did NOT check"] + ["- " + x for x in NOT_CHECKED]
    L.append("Evidence labels: L2 = exact parser or decoder output; L2h = keyword or name-list match (heuristic). Neither is a judgement. " + SCOPE_NOTE)
    return L

def engine_error(e, raw_sha=None):
    return dict(result="ENGINE_ERROR", error=type(e).__name__, reason="the engine stopped (%s); no assessment of the input was made. Do not substitute a model-written assessment." % type(e).__name__,
                meta=dict(engine=ENGINE_VERSION, ruleset=RULESET, input_sha256=raw_sha, run=now_stamp()), components=[], facts=[])

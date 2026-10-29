"""rcpt facts: fact store + exact extractors (L2) and keyword extractors (L2h)."""
import re, json, base64, binascii, html, urllib.parse, codecs, ipaddress, unicodedata
from core import *

class Inv:
    def __init__(s): s.facts = []; s.counts = {}; s.truncated = {}; s.notes = []; s.seen = set(); s.ordinal = 0
    def add(s, kind, comp, line, value, level="L2", sub="", extra=None, method="", sensitive=False, key=None):
        """sensitive=True (secrets, e-mail addresses): the value is never hashed or stored; the id comes from position only."""
        tick()
        if s.counts.get(kind, 0) >= LIMITS["max_facts_per_kind"]: s.truncated[kind] = s.truncated.get(kind, 0) + 1; return None
        s.ordinal += 1
        basis = ("pos%d" % s.ordinal) if sensitive else sha(key if key is not None else str(value))
        fid = "F-" + sha("|".join([kind, sub, comp, str(line), basis]))[:10]
        if fid in s.seen: return None
        s.seen.add(fid); s.counts[kind] = s.counts.get(kind, 0) + 1
        f = dict(fid=fid, kind=kind, sub=sub, level=level, component=comp, line=line, value=esc(value), method=method or kind)
        if not sensitive: f["vsha"] = sha(key if key is not None else str(value))[:16]
        if extra: f.update(extra)
        s.facts.append(f); return f

_UC = r"(?:\[\.\]|\[:\]|\(\.\)|[^\s<>\"'`)\]}])"
URL_RX = re.compile(r"(?i)\b(?:https?|hxxps?|ftp|wss?)(?::|\[:\])//" + _UC + "{1,2000}|\\bwww\\." + _UC + "{3,500}")
SHORTENERS = {"bit.ly","t.co","tinyurl.com","goo.gl","is.gd","ow.ly","buff.ly","rebrand.ly","cutt.ly","shorturl.at","rb.gy","tiny.cc"}
EMAIL_RX = re.compile(r"(?i)\b[a-z0-9._%+-]{1,64}@[a-z0-9-]+(?:\.[a-z0-9-]+)+\b")
RECIP_CTX = re.compile(r"(?i)\b(bcc|cc|to|forward\w*|copy|copies|send\w*|email\w*|archive|notify|reply)\b[^.\n]{0,60}$")

def extract_urls(inv, comp, text, via=""):
    for m in URL_RX.finditer(text):
        tick(); raw = m.group(0).rstrip(".,;:!?")
        u = raw.replace("[:]", ":").replace("[.]", ".").replace("(.)", ".")
        defanged = u != raw or u.lower().startswith("hxx")
        if u.lower().startswith("hxx"): u = "http" + u[3:]
        if u.lower().startswith("www."): u = "http://" + u
        try: sp = urllib.parse.urlsplit(u); host = (sp.hostname or "").lower(); port = sp.port
        except Exception as e:
            inv.add("url", comp, lineno(text, m.start()), raw, sub="unparseable", extra=dict(via=via, error=type(e).__name__), method="urlsplit"); continue
        hk = "domain"
        try: ipaddress.ip_address(host); hk = "ip_literal"
        except ValueError:
            if host.startswith("xn--") or ".xn--" in host: hk = "punycode"
            elif any(ord(c) > 127 for c in host): hk = "non_ascii"
            elif host == "localhost" or host.endswith((".local", ".internal")): hk = "internal_name"
        q = urllib.parse.parse_qsl(sp.query, keep_blank_values=True)[:20]
        inv.add("url", comp, lineno(text, m.start()), host + (":%s" % port if port else ""), sub=sp.scheme.lower() or "none",
                extra=dict(host=esc(host), host_kind=hk, scheme=sp.scheme.lower(), userinfo=("@" in sp.netloc), shortener=host in SHORTENERS, query_keys=[esc(k, 40) for k, _ in q],
                           templated=bool(re.search(r"\{|<|%7[Bb]|\$\(", u)), defanged=defanged, via=via), method="urlsplit-exact-host", key=u)

def extract_recipients(inv, comp, text, via=""):
    for m in EMAIL_RX.finditer(text):
        tick(); addr = m.group(0).lower(); dom = addr.split("@", 1)[1]
        ctx = RECIP_CTX.search(text[max(0, m.start() - 80):m.start()]); role = "unspecified"
        if ctx:
            w = ctx.group(1).lower(); role = "bcc" if w == "bcc" else "cc" if w == "cc" else "forward" if (w.startswith("forward") or w in ("copy", "copies", "archive")) else "to"
        inv.add("recipient" if ctx else "email_address", comp, lineno(text, m.start()), "[local part withheld]@" + dom, sub=role, extra=dict(domain=esc(dom), role=role, via=via), method="email-pattern", sensitive=True)

SECRET_PATS = [("aws_access_key", r"\bAKIA[0-9A-Z]{16}\b"), ("github_token", r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"), ("slack_token", r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),
  ("sk_style_key", r"\bsk-[A-Za-z0-9_-]{20,}\b"), ("private_key_block", r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), ("bearer_token", r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{20,}"),
  ("assigned_secret", r"(?i)\b(?:api[_-]?key|secret|token|passw(?:or)?d|passphrase|seed phrase)\b\s*[:=]\s*[\"']?([^\s\"']{8,})"), ("jwt", r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")]
SECRET_RX = [(n, re.compile(p)) for n, p in SECRET_PATS]
PLACEHOLDER = re.compile(r"[<\[{(*x.-]+.*|your[_-].*|\$\{?\w+\}?|.*(?:example|placeholder|changeme|xxxx).*", re.I)
def mask(s):
    s = str(s); return ("%s...(len %d)" % (s[:3], len(s))) if len(s) >= 20 else "[secret len %d]" % len(s)
def extract_secrets(inv, comp, text, via=""):
    for n, rx in SECRET_RX:
        for m in rx.finditer(text):
            tick(); g = m.group(1) if m.groups() else m.group(0)
            if n == "assigned_secret" and PLACEHOLDER.fullmatch(g): continue
            inv.add("secret", comp, lineno(text, m.start()), mask(g), level="L2h", sub=n, extra=dict(via=via, length=len(g)), method="secret-pattern", sensitive=True)

# ---- capability mentions (keyword, L2h) with clause-level negation ----
CAPS = [
 ("SEND", r"\b(?:send|sends|sending|forward|forwards|forwarding|dm|dms)\b|\be-?mail(?:s|ing)?\s+(?:it|them|the|a|an|your|my|each|every|all|this|that|\S+@)|\breply\s+to\b|\brespond\s+to\b"),
 ("POST", r"\b(?:post|posts|posting|tweet|tweets|tweeting|publish|publishes|publishing|retweet|broadcast)\b"),
 ("PAY", r"\b(?:pay|pays|paying|buy|buys|buying|purchase|purchases|purchasing|transfer funds|send money|move money|place an? order)\b"),
 ("DELETE", r"\b(?:delete|deletes|deleting|erase|wipe|purge|rm -rf|drop table|remove permanently)\b"),
 ("EXEC", r"\b(?:run|runs|running|execute|executes)\s+(?:\w+\s+){0,2}(?:script|command|shell|code|program)s?\b|\b(?:shell|bash|subprocess|os\.system|eval\(|curl\s|wget\s|pip install|npm install|sudo)\b"),
 ("CODE_PUSH", r"\b(?:git push|force-push|merge the pr|merge (?:the )?pull request|deploy|publish (?:the )?package|push to main)\b"),
 ("CREATE_ROUTINE", r"\b(?:create|add|schedule|set up|make|update|edit)\s+(?:\w+\s+){0,2}(?:routines?|automations?|scheduled tasks?|cron jobs?)\b|\bUpdateRoutine\b"),
 ("CREATE_SKILL", r"\b(?:create|add|write|install|save)\s+(?:\w+\s+){0,2}skills?\b"),
 ("CREATE_AGENT", r"\b(?:create|spawn|launch|start|add)\s+(?:\w+\s+){0,2}(?:bots?|agents?|sub-?agents?)\b|\bSendToAgent\b"),
 ("SETTINGS_CHANGE", r"\b(?:change|disable|turn off|edit|update|modify)\s+(?:\w+\s+){0,2}(?:auto-?review|approvals?|permissions?|settings)\b")]
CAP_RX = [(c, re.compile(p, re.I)) for c, p in CAPS]
HIGH_IMPACT = {c for c, _ in CAPS}
# Clause-level negation: the negator must sit directly in front of the verb (optionally one adverb and "to"), inside the same clause.
# Clause breaks: . ; : , ! ? newline. So "Do not hesitate to send", "Never mind X, send", "Don't wait; forward" stay capabilities.
NEG_DIRECT = re.compile(r"(?i)(?:\b(?:never|not|cannot|can't|won't|mustn't|shouldn't|shan't|will not|must not|should not|shall not|do not|don't|does not|doesn't|did not|didn't|not allowed to|forbidden to|refuse to|unable to|no ability to)\s+(?:(?:ever|automatically|directly|publicly|silently|again)\s+)?(?:to\s+)?)$")
CLAUSE_BREAK = re.compile(r"[.;:!?\n,]")
def clause_before(text, pos):
    a = 0
    for m in CLAUSE_BREAK.finditer(text, max(0, pos - 120), pos): a = m.end()
    return text[a if a else max(0, pos - 120):pos]
def sentence_at(text, pos):
    a = max(text.rfind(".", 0, pos), text.rfind("\n", 0, pos), text.rfind("!", 0, pos), text.rfind("?", 0, pos)) + 1
    m = re.search(r"[.!?\n]", text[pos:pos + 400]); b = pos + (m.start() if m else min(400, len(text) - pos))
    return text[a:b].strip()
UNTRUSTED = [
 ("email", r"\b(?:read|check|scan|monitor|triage|process|summari[sz]e|watch|open|go through)\w*\s+(?:\w+\s+){0,3}(?:e-?mails?|inbox|mail|newsletters?)\b|\bincoming\s+(?:e-?mail|mail)\b|\bunread\s+e-?mails?\b|\binbox\b"),
 ("web", r"\b(?:browse|search the web|web search|scrape|crawl|fetch\w*|open\s+(?:\w+\s+){0,2}(?:links?|urls?|pages?|sites?|websites?)|read\s+(?:\w+\s+){0,2}(?:pages?|articles?|websites?))\b"),
 ("x_content", r"\b(?:timeline|mentions|replies|direct messages|x posts|tweets|bookmarks)\b"),
 ("inbound_chat", r"\b(?:slack|teams|telegram|whatsapp|discord|imessage|sms|text messages?)\b"),
 ("shared_docs", r"\b(?:shared (?:docs?|documents?|files?|drive)|google drive|attachments?|uploaded files?)\b"),
 ("webhook", r"\bwebhooks?\b")]
UNTRUSTED_RX = [(c, re.compile(p, re.I)) for c, p in UNTRUSTED]
APPROVAL_DECL = re.compile(r"(?i)\b(?:ask|confirm|check with|get|wait for|require|request|need)\w*\s+(?:\w+\s+){0,3}(?:approval|confirmation|permission|go-?ahead|okay|sign-?off)\b|\bdrafts?\s+only\b|\bas a draft\b|\bfor my (?:review|approval)\b|\bapproval card\b|\bbefore (?:sending|posting|paying|deleting|publishing)\b|\bask (?:me|the owner|the user) first\b")
APPROVAL_WAIVE = re.compile(r"(?i)\b(?:without|no need (?:for|to)|skip|bypass|don't|do not|never)\s+(?:\w+\s+){0,2}(?:asking|ask|confirm\w*|approval|permission|waiting|wait|checking|review)\b|\bauto-?approve|\bjust go ahead\b")
def approval_state(text):
    d = bool(APPROVAL_DECL.search(text)); w = bool(APPROVAL_WAIVE.search(text))
    return "mixed" if d and w else "declared" if d else "waived" if w else "none_found"

def extract_caps(inv, comp, text, via=""):
    for c, rx in CAP_RX:
        for m in rx.finditer(text):
            tick(); pre = clause_before(text, m.start()); neg = bool(NEG_DIRECT.search(pre)); sent = sentence_at(text, m.start())
            inv.add("prohibition" if neg else "capability", comp, lineno(text, m.start()), c, level="L2h", sub=c,
                    extra=dict(cls=c, quote=esc(sent, 140), draft_in_sentence=bool(re.search(r"(?i)\bdraft", sent)), via=via), method="capability-keywords/clause-negation", key=c + "|" + sent)
    for ch, rx in UNTRUSTED_RX:
        m = rx.search(text)
        if m: inv.add("untrusted_input", comp, lineno(text, m.start()), ch, level="L2h", sub=ch, extra=dict(basis="text-mention", quote=esc(sentence_at(text, m.start()), 140), via=via), method="input-channel-keywords", key=ch)

# ---- hidden / encoded text (exact decoders, L2) ----
B64_RX = re.compile(r"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{24,}={0,2}(?![A-Za-z0-9+/_-])")
HEX_RX = re.compile(r"(?<![0-9a-fA-F])(?:[0-9a-fA-F]{2}){16,}(?![0-9a-fA-F])")
PCT_RX = re.compile(r"(?:%[0-9A-Fa-f]{2}){6,}"); ENT_RX = re.compile(r"(?:&#x?[0-9a-fA-F]+;){6,}"); UESC_RX = re.compile(r"(?:\\u[0-9a-fA-F]{4}){4,}"); HEXESC_RX = re.compile(r"(?:\\x[0-9a-fA-F]{2}){8,}")
ZW_RUN = re.compile("[\u200b\u200c\u200d\u2060\u2061\u2062\u2063\u2064\ufeff\u00ad\u180e\u034f\u115f\u1160\u3164\uffa0\u200e\u200f\u061c\u202a-\u202e\u2066-\u2069\ufe00-\ufe0f]+")
def printable_text(b):
    try: s = b.decode("utf-8")
    except UnicodeDecodeError: return None
    if len(s) < 4: return None
    return s if sum(1 for c in s if c.isprintable() or c in "\n\t\r") / len(s) >= 0.9 else None
def decode_candidates(text, budget):
    out = []
    for m in B64_RX.finditer(text):
        tick(); tok = m.group(0)
        if re.fullmatch(r"[0-9a-fA-F]+", tok) or re.fullmatch(r"[A-Za-z]+", tok) or re.fullmatch(r"[a-z0-9-]+", tok) or tok.count("/") > 3: continue
        t2 = tok.replace("-", "+").replace("_", "/"); t2 += "=" * (-len(t2) % 4)
        try: b = base64.b64decode(t2, validate=True)
        except (binascii.Error, ValueError): continue
        out.append(("base64", m.start(), b))
        if len(out) >= budget: return out
    for rx, name, fn in [(HEX_RX, "hex", bytes.fromhex), (PCT_RX, "percent", urllib.parse.unquote_to_bytes),
                         (ENT_RX, "html-entity", lambda s: html.unescape(s).encode("utf-8", "replace")),
                         (UESC_RX, "unicode-escape", lambda s: codecs.decode(s, "unicode_escape").encode("utf-8", "replace")),
                         (HEXESC_RX, "hex-escape", lambda s: bytes(int(x, 16) for x in re.findall(r"\\x([0-9a-fA-F]{2})", s)))]:
        for m in rx.finditer(text):
            tick()
            if name == "hex" and len(m.group(0)) in (32, 40, 56, 64, 96, 128): continue
            try: out.append((name, m.start(), fn(m.group(0))))
            except Exception: pass
            if len(out) >= budget: return out
    return out
def scan_decoded(inv, comp, text, depth, via, state, comment=False):
    if depth > LIMITS["decode_depth"]: inv.notes.append("decode_depth_reached"); return
    extract_urls(inv, comp, text, via); extract_recipients(inv, comp, text, via); extract_secrets(inv, comp, text, via); extract_caps(inv, comp, fold(text), via)
    if depth < LIMITS["decode_depth"] and not comment: hidden_facts(inv, comp, text, depth + 1, via, state)
def hidden_facts(inv, comp, text, depth=0, via="", state=None):
    state = state if state is not None else dict(bytes=0, cands=0)
    for m in ZW_RUN.finditer(text):
        tick(); run = m.group(0); cps = sorted(set(ord(c) for c in run))
        if cps == [0x200D] and len(run) <= 3: continue
        if cps == [0xFE0F] and len(run) <= 2: continue
        dec = None
        if len(run) >= 16 and len(cps) == 2:
            bits = "".join("1" if ord(c) == cps[1] else "0" for c in run)
            for fl in (bits, "".join("1" if b == "0" else "0" for b in bits)):
                s = printable_text(bytes(int(fl[i:i + 8], 2) for i in range(0, len(fl) - 7, 8)))
                if s: dec = s; break
        inv.add("hidden_text", comp, lineno(text, m.start()), "invisible run x%d" % len(run), sub="bidi_control" if all(ord(c) in BIDI for c in run) else "invisible_run",
                extra=dict(count=len(run), codepoints=["U+%04X" % c for c in cps[:8]], decoded_bits=esc(dec, 100) if dec else None, via=via), method="invisible-scan", key="%s|%d|%s" % (comp, m.start(), cps))
        if dec: scan_decoded(inv, comp, dec, depth, via + ">zero-width-bits", state)
    i = 0; n = len(text)
    while i < n:
        if is_tag(ord(text[i])):
            j = i; dec = ""
            while j < n and is_tag(ord(text[j])):
                c = ord(text[j]) - 0xE0000; dec += chr(c) if 32 <= c < 127 else ""; j += 1
            if not (i > 0 and text[i - 1] == "\U0001F3F4") or len(dec) > 8:
                inv.add("hidden_text", comp, lineno(text, i), "unicode tag chars x%d" % (j - i), sub="unicode_tags", extra=dict(decoded=esc(dec, 140), via=via), method="tag-decode", key=comp + "|%d|" % i + dec)
                if dec: scan_decoded(inv, comp, dec, depth, via + ">unicode-tags", state)
            i = j
        else: i += 1
    for m in re.finditer(r"<!--(.{0,4000}?)-->", text[:LIMITS["scan_chars"]], re.S):
        tick(); inv.add("hidden_text", comp, lineno(text, m.start()), "html comment", sub="html_comment", extra=dict(content=esc(m.group(1), 160), via=via), method="comment-scan", key=m.group(1))
        scan_decoded(inv, comp, m.group(1), depth, via + ">html-comment", state, comment=True)
    for m in re.finditer(r"(?is)<(\w{1,12})\b[^<>]{0,200}?(?:hidden|display\s*:\s*none|font-size\s*:\s*0)[^<>]{0,200}>(.{0,4000}?)</\1>", text[:LIMITS["scan_chars"]]):
        inv.add("hidden_text", comp, lineno(text, m.start()), "hidden html element", sub="hidden_html", extra=dict(content=esc(m.group(2), 160), via=via), method="comment-scan", key=m.group(2))
    for tok in re.findall(r"[^\W\d_]{4,40}", text[:LIMITS["scan_chars"]]):
        tick(); sc = set()
        for c in tok:
            if ord(c) > 127:
                nm = unicodedata.name(c, ""); sc.add("CYRILLIC" if "CYRILLIC" in nm else "GREEK" if "GREEK" in nm else "OTHER")
            else: sc.add("LATIN")
        if "LATIN" in sc and sc & {"CYRILLIC", "GREEK"}:
            inv.add("hidden_text", comp, 0, "mixed-script token", sub="mixed_script", extra=dict(token=esc(tok, 40), via=via), method="script-mix", key=comp + tok)
    if depth < LIMITS["decode_depth"]:
        for name, pos, b in decode_candidates(text, max(0, LIMITS["decode_candidates"] - state["cands"])):
            state["cands"] += 1; state["bytes"] += len(b)
            if state["bytes"] > LIMITS["decode_bytes"]: inv.notes.append("decode_budget_reached"); break
            s = printable_text(b)
            if s:
                inv.add("hidden_text", comp, lineno(text, pos), "%s decoded" % name, sub="encoded_" + name, extra=dict(decoded=esc(s, 160), via=via), method="decoders:" + name, key=comp + "|%d|" % pos + s)
                scan_decoded(inv, comp, s, depth + 1, via + ">" + name, state)
            elif len(b) >= 24:
                inv.add("hidden_text", comp, lineno(text, pos), "%s blob (binary, %d bytes)" % (name, len(b)), sub="encoded_binary", extra=dict(size=len(b), via=via), method="decoders:" + name, key=comp + "|%d" % pos + sha(b))

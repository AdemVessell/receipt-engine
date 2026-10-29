"""rcpt inventory: text/JSON template -> components + facts -> report. No verdicts. v1 scope: text inventory only."""
import re, json, time
from core import *
from facts import *

PLUGIN_TABLE = {"gmail": (["email"], ["SEND"]), "outlook": (["email"], ["SEND"]), "email": (["email"], ["SEND"]), "slack": (["inbound_chat"], ["POST"]), "teams": (["inbound_chat"], ["POST"]),
 "telegram": (["inbound_chat"], ["SEND"]), "whatsapp": (["inbound_chat"], ["SEND"]), "discord": (["inbound_chat"], ["POST"]), "x": (["x_content"], ["POST", "SEND"]), "twitter": (["x_content"], ["POST", "SEND"]),
 "x-money": ([], ["PAY"]), "xmoney": ([], ["PAY"]), "github": ([], ["CODE_PUSH"]), "browser": (["web"], []), "web": (["web"], []), "shell": ([], ["EXEC"]), "computer": ([], ["EXEC"]),
 "terminal": ([], ["EXEC"]), "drive": (["shared_docs"], ["DELETE"]), "gdrive": (["shared_docs"], ["DELETE"])}
TRIGGER_UNTRUSTED = {"email": "yes", "webhook": "yes", "slack": "yes", "microsoftteams": "yes", "github": "maybe", "origin": "maybe", "linear": "maybe", "sentry": "maybe", "cron": "no", "schedule": "no", "rrule": "no"}
# v0.2.2: field names accepted as the schedule of a routine, in priority order (case-insensitive). "trigger" counts only when its value is a schedule string or holds one.
SCHED_KEYS = ("schedule", "cron", "cron_expression", "cronexpression", "rrule", "recurrence", "every", "frequency", "interval")
ROUTINE_KNOWN = {"name", "instruction", "prompt", "schedule", "trigger", "cron", "cron_expression", "cronexpression", "rrule", "recurrence", "every", "frequency", "interval"}
SCHED_INNER = ("cron", "cron_expression", "cronexpression", "expression", "schedule", "rrule", "recurrence", "every", "frequency", "interval")

def parse_field(f, lo, hi):
    vals = set()
    for part in f.split(","):
        step = 1
        if "/" in part: part, st = part.split("/", 1); step = int(st)
        if part == "*": a, b = lo, hi
        elif "-" in part: a, b = [int(x) for x in part.split("-", 1)]
        else: a = b = int(part)
        if a < lo or b > hi or a > b or step < 1: raise ValueError
        vals |= set(range(a, b + 1, step))
    return vals
RR_DAYS = {"MO", "TU", "WE", "TH", "FR", "SA", "SU"}
def parse_rrule(s):
    """RFC 5545-style recurrence text (FREQ/INTERVAL/BYDAY/BYHOUR/BYMINUTE). Returns None when it is not one."""
    t = re.sub(r"(?i)^\s*(?:RRULE|DTSTART[^\n]*\n\s*RRULE)\s*:", "", s.strip()); kv = {}
    for part in re.split(r"[;\n]", t):
        if "=" in part: k, v = part.split("=", 1); kv[k.strip().upper()] = v.strip().upper()
    fr = kv.get("FREQ")
    if fr not in ("MINUTELY", "HOURLY", "DAILY", "WEEKLY", "MONTHLY", "YEARLY"): return None
    try: iv = max(1, int(kv.get("INTERVAL", "1")))
    except ValueError: return None
    days = [d[-2:] for d in kv.get("BYDAY", "").split(",") if d[-2:] in RR_DAYS]; nh = len([x for x in kv.get("BYHOUR", "").split(",") if x.strip()]) or 1; nm = len([x for x in kv.get("BYMINUTE", "").split(",") if x.strip()]) or 1
    per_day = {"MINUTELY": 1440 / iv, "HOURLY": 24 / iv, "DAILY": nh * nm / iv, "WEEKLY": nh * nm * (len(days) or 1) / 7 / iv, "MONTHLY": nh * nm / 30.4 / iv, "YEARLY": nh * nm / 365 / iv}[fr]
    return dict(kind="rrule", freq=fr, avg_runs_per_day=round(per_day, 3), weekdays_only=(set(days) == {"MO", "TU", "WE", "TH", "FR"}))
def parse_schedule(s):
    s = (s or "").strip()
    if not s: return dict(kind="none")
    rr = parse_rrule(s) if re.search(r"(?i)\bFREQ\s*=", s) else None
    if rr: return rr
    p = s.split()
    if len(p) == 5:
        try:
            mi = parse_field(p[0], 0, 59); ho = parse_field(p[1], 0, 23); dom = parse_field(p[2], 1, 31); mo = parse_field(p[3], 1, 12); dw = parse_field(p[4], 0, 7)
            dw = {0 if d == 7 else d for d in dw}
            return dict(kind="cron", runs_per_active_day=len(mi) * len(ho), avg_runs_per_day=round(len(mi) * len(ho) * (len(dw) / 7) * (len(dom) / 31) * (len(mo) / 12), 3), weekdays_only=(dw == {1, 2, 3, 4, 5}))
        except Exception: pass
    t = s.lower(); m = re.search(r"every\s+(\d+)\s*(?:minutes?|mins?|m)\b", t)
    if m: return dict(kind="natural", avg_runs_per_day=round(1440 / max(1, int(m.group(1))), 2))
    m = re.search(r"every\s+(\d+)\s*(?:hours?|hrs?|h)\b", t)
    if m: return dict(kind="natural", avg_runs_per_day=round(24 / max(1, int(m.group(1))), 2))
    if re.search(r"\b(hourly|every hour)\b", t): return dict(kind="natural", avg_runs_per_day=24)
    if re.search(r"\b(daily|every day|every morning|every evening|every night)\b", t): return dict(kind="natural", avg_runs_per_day=1)
    if re.search(r"\b(weekdays?|monday to friday)\b", t): return dict(kind="natural", avg_runs_per_day=0.714, weekdays_only=True)
    if re.search(r"\b(weekly|every (?:mon|tues|wednes|thurs|fri|satur|sun)day)\b", t): return dict(kind="natural", avg_runs_per_day=0.143)
    return dict(kind="unparsed", raw=esc(s, 80))
def trigger_types(tr):
    types = []
    def walk(x):
        if isinstance(x, dict):
            if isinstance(x.get("type"), str): types.append(x["type"].lower())
            for v in x.values():
                if isinstance(v, (dict, list)): walk(v)
        elif isinstance(x, list):
            for v in x: walk(v)
    if isinstance(tr, (dict, list)): walk(tr)
    elif isinstance(tr, str) and tr.strip():
        for k in TRIGGER_UNTRUSTED:
            if re.search(r"\b%s\b" % k, tr, re.I): types.append(k)
        if not types: types.append("unrecognized")
    return types

def S(v, cap=200_000):
    if v is None: return ""
    if isinstance(v, str): return v[:cap]
    try: return json.dumps(v, ensure_ascii=False, default=str)[:cap]
    except Exception: return repr(type(v))
KNOWN_TOP = {"name", "description", "title", "instructions", "memories", "skills", "routines", "plugins", "meta", "template", "avatar", "avatarColor", "avatarShape", "gettingStarted"}
def _is_sched_string(v):
    if not isinstance(v, str) or not v.strip(): return False
    return parse_schedule(v)["kind"] in ("cron", "rrule", "natural")
def routine_schedule(x):
    """v0.2.2: find the schedule of a routine entry under any accepted field name. Returns (schedule value, trigger value, field used, other schedule fields seen)."""
    low = {str(k).lower(): k for k in x}; found = [(k, x[low[k]]) for k in SCHED_KEYS if k in low and x[low[k]] not in (None, "")]
    trig = x.get("trigger"); sched = None; skey = None
    if found: skey, sched = found[0]
    if isinstance(sched, dict):   # {"cron": "..."} / {"type": "cron", "expression": "..."}
        inner = next((v for k in SCHED_INNER for kk, v in sched.items() if str(kk).lower() == k and isinstance(v, str) and v.strip()), None)
        if inner is not None: skey = "%s.%s" % (skey, next(kk for kk, v in sched.items() if v is inner)); sched = inner
    if isinstance(sched, str) and skey in ("every", "frequency", "interval") and not re.search(r"(?i)\bevery\b|\bFREQ=", sched): sched = "every " + sched
    if sched is None and trig is not None:   # trigger used as a schedule alias
        if _is_sched_string(trig): sched, skey, trig = trig, "trigger", None
        elif isinstance(trig, dict):
            inner = next((v for k in SCHED_INNER for kk, v in trig.items() if str(kk).lower() == k and _is_sched_string(v)), None)
            if inner is not None: sched, skey = inner, "trigger." + next(kk for kk, v in trig.items() if v is inner)
    return sched, trig, skey, [k for k, _ in found[1:]]
def build_components(inv, obj):
    comps = []
    def C(cid, kind, name, text, struct=None): comps.append(dict(id=cid, kind=kind, name=name, text=text, struct=struct))
    if isinstance(obj, dict) and isinstance(obj.get("template"), dict): obj = obj["template"]
    if not isinstance(obj, dict):
        inv.add("schema", "input", 0, "top-level JSON is %s, expected object" % type(obj).__name__, sub="type_mismatch"); C("input:raw", "unknown", "raw", S(obj)); return comps
    meta = obj.get("meta") if isinstance(obj.get("meta"), dict) else {}
    for k in ("name", "description", "title"):
        v = obj.get(k, meta.get(k))
        if v not in (None, ""): C("meta:" + k, "meta", k, S(v))
    if "instructions" in obj: C("instructions", "instructions", "instructions", S(obj["instructions"]))
    def lst(key):
        v = obj.get(key)
        if v is None: return []
        if isinstance(v, list): return v
        inv.add("schema", key, 0, "%s is %s, expected list" % (key, type(v).__name__), sub="type_mismatch"); return [v]
    for i, x in enumerate(lst("memories"), 1): C("memory:%d" % i, "memory", "memory %d" % i, S(x.get("text", x) if isinstance(x, dict) else x))
    seen = {}
    def uname(kind, base):
        base = esc(base, 60) or "unnamed"; n = seen.get((kind, base), 0); seen[(kind, base)] = n + 1
        return base if n == 0 else "%s#%d" % (base, n + 1)
    for x in lst("skills"):
        if not isinstance(x, dict): inv.add("schema", "skills", 0, "skill entry is %s" % type(x).__name__, sub="type_mismatch"); C("skill:?", "skill", "?", S(x)); continue
        nm = uname("skill", S(x.get("name", "?"), 80))
        for k, v in x.items(): C("skill:%s/%s" % (nm, esc(k, 30)), "skill", nm, S(v))
    for x in lst("routines"):
        if not isinstance(x, dict): inv.add("schema", "routines", 0, "routine entry is %s" % type(x).__name__, sub="type_mismatch"); C("routine:?", "routine", "?", S(x)); continue
        nm = uname("routine", S(x.get("name", "?"), 80))
        sched, trig, skey, extra_keys = routine_schedule(x)
        C("routine:" + nm, "routine", nm, S(x.get("instruction", x.get("prompt", ""))), struct=dict(schedule=sched, trigger=trig, schedule_field=skey))
        for k in extra_keys: inv.add("schema", "routine:" + nm, 0, k, sub="multiple_schedule_fields")
        for k in x:
            if str(k).lower() not in ROUTINE_KNOWN: inv.add("schema", "routine:" + nm, 0, k, sub="unknown_field"); C("routine:%s/%s" % (nm, esc(k, 30)), "routine", nm, S(x[k]))
    for x in lst("plugins"):
        d = x if isinstance(x, dict) else dict(name=S(x))
        nm = uname("plugin", S(d.get("name", d.get("id", "?")), 80)); C("plugin:" + nm, "plugin", nm, S(x), struct=d)
    for k, v in obj.items():
        if k not in KNOWN_TOP: inv.add("schema", "input", 0, k, sub="unknown_field"); C("unknown:" + esc(k, 40), "unknown", k, S(v))
    return comps

def plugin_facts(inv, c):
    d = c["struct"]; toks = set(re.findall(r"[a-z0-9-]+", " ".join(S(d.get(k, "")).lower() for k in ("name", "id")))); hit = next((k for k in PLUGIN_TABLE if k in toks), None)
    chans, imp = PLUGIN_TABLE[hit] if hit else ([], [])
    inv.add("plugin", c["id"], 0, S(d.get("name", d.get("id", "?")), 80), level="L2", sub="listed_entry",
            extra=dict(listed_in_plugins_field=True, name_list_match=hit, name_list_classes=imp, name_list_channels=chans,
                       class_basis=("L2h name list: guess from the name only" if hit else "unclassified: capabilities UNKNOWN, not 'none'")), method="plugins-field")
    cmd = S(d.get("command", ""))
    if re.search(r"\b(npx|uvx|pipx|bunx)\b", cmd):
        inv.add("plugin_launcher", c["id"], 0, esc(cmd, 100), sub="pinned" if re.search(r"@\d|==\d|@[0-9a-f]{7,}", cmd) else "unpinned", method="launcher-pattern")
    for ch in chans: inv.add("untrusted_input", c["id"], 0, ch, level="L2h", sub=ch, extra=dict(basis="plugin name list", via=""), method="plugin-name-list", key=ch + "|plugin")
    for cl in imp: inv.add("capability", c["id"], 0, cl, level="L2h", sub=cl, extra=dict(cls=cl, quote="via plugin name list", draft_in_sentence=False, basis="plugin name list", via=""), method="plugin-name-list", key=cl + "|plugin")
def routine_facts(inv, c):
    st = c["struct"] or {}; sched = S(st.get("schedule")); ps = parse_schedule(sched); types = trigger_types(st.get("trigger"))
    infl = [TRIGGER_UNTRUSTED.get(t, "maybe") for t in types]
    caps = sorted({f["cls"] for f in inv.facts if f["kind"] == "capability" and f["component"] == c["id"]})
    inv.add("routine", c["id"], 0, c["name"], sub="structured", extra=dict(schedule=ps, schedule_raw=esc(sched, 60), schedule_field=st.get("schedule_field") or "none", trigger_types=types,
            trigger_influenceable_by_outsiders=("yes" if "yes" in infl else "maybe" if "maybe" in infl else "no" if infl else "n/a"),
            approval_wording_in_text=approval_state(c["text"]), capability_keywords_in_text=caps), method="routine-fields", key=c["id"] + "|" + sched + "|" + ",".join(types))
    if sched.strip() and ps["kind"] == "unparsed": inv.add("schema", c["id"], 0, "schedule not parsed", sub="schedule_unparsed")
    if not sched.strip() and not types: inv.add("schema", c["id"], 0, "routine has neither schedule nor trigger field", sub="no_trigger_field")
def scan_component(inv, c):
    raw = c["text"]; c["sha_raw"] = sha(raw); c["sha_norm"] = sha(norm(raw)); c["size"] = len(raw); c["invisible"] = sum(1 for ch in raw if ord(ch) in ZW or is_tag(ord(ch)))
    if not raw.strip() and c["kind"] != "plugin": inv.add("schema", c["id"], 0, "component has no text", sub="no_text"); return
    if len(raw) > LIMITS["scan_chars"]:
        inv.add("schema", c["id"], 0, "component %d chars; scanned first %d" % (len(raw), LIMITS["scan_chars"]), sub="truncated"); raw = raw[:LIMITS["scan_chars"]]
    folded = fold(raw)
    letters = [ch for ch in raw if ch.isalpha()]
    if len(letters) >= 40 and sum(1 for ch in letters if ord(ch) < 0x250) / len(letters) < 0.5: inv.add("schema", c["id"], 0, "mostly non-Latin text; keyword lists are English only", sub="language_note")
    extract_urls(inv, c["id"], raw); extract_recipients(inv, c["id"], raw); extract_secrets(inv, c["id"], raw)
    hidden_facts(inv, c["id"], raw)
    if c["kind"] != "plugin": extract_caps(inv, c["id"], folded)
    if c["kind"] == "plugin": plugin_facts(inv, c)
    if c["kind"] == "routine" and c["struct"] is not None: routine_facts(inv, c)

def inventory(raw, expect_bytes=None, expect_sha=None):
    t0 = time.time(); inv = Inv(); meta = dict(bytes=len(raw), input_sha256=sha(raw), engine=ENGINE_VERSION, ruleset=RULESET, run=now_stamp())
    res = dict(result="OK", meta=meta, components=[], facts=[], limits_hit={})
    if expect_bytes is not None and expect_bytes != len(raw):
        res.update(result="MATERIALIZATION_MISMATCH", reason="file has %d bytes but %d were expected; the text was probably truncated or altered while being written. Nothing was scanned." % (len(raw), expect_bytes)); return res
    if expect_sha and expect_sha.lower() != meta["input_sha256"]:
        res.update(result="MATERIALIZATION_MISMATCH", reason="file sha256 differs from the expected value. Nothing was scanned."); return res
    if len(raw) > LIMITS["max_bytes"]:
        res.update(result="INPUT_TOO_LARGE", reason="input %d bytes > limit %d; nothing was scanned" % (len(raw), LIMITS["max_bytes"])); return res
    text = raw.decode("utf-8", errors="replace"); meta["replacement_chars_in_decoded_text"] = text.count("\ufffd") - raw.count(b"\xef\xbf\xbd")
    obj = None; kind = "pasted_text"
    if text.lstrip("\ufeff \t\r\n")[:1] in ("{", "["):
        try: obj = json.loads(text); kind = "json"
        except Exception as e: inv.add("schema", "input", 0, "looks like JSON but did not parse: %s" % type(e).__name__, sub="json_parse_failed")
    meta["input_kind"] = kind
    meta["structure"] = "structured JSON: components are as labelled by the input" if kind == "json" else "unstructured text: routines, plugins and memories are NOT identified; items are text mentions"
    comps = build_components(inv, obj) if kind == "json" else [dict(id="text", kind="text", name="text", text=text, struct=None)]
    if len(comps) > 500: inv.add("schema", "input", 0, "%d components; first 500 scanned" % len(comps), sub="truncated"); comps = comps[:500]
    for c in comps: scan_component(inv, c)
    res["components"] = [dict(id=c["id"], kind=c["kind"], size=c.get("size", 0), sha256=c.get("sha_raw", ""), sha256_normalized=c.get("sha_norm", ""), invisible_chars=c.get("invisible", 0)) for c in comps]
    res["facts"] = inv.facts; res["limits_hit"] = dict(truncated_kinds=inv.truncated, notes=sorted(set(inv.notes)))
    if inv.truncated or inv.notes or any(f["kind"] == "schema" and f["sub"] == "truncated" for f in inv.facts): res["result"] = "PARTIAL"
    meta["duration_s"] = round(time.time() - t0, 3)
    return res

def render_inventory(res):
    m = res["meta"]; L = ["# Receipt report - inventory", "This is a list of facts found in the text supplied. It makes no judgement of the template or its author.", ""]
    L += ["## Run record (made by the same program that wrote this report; it is not proof of who ran what)", "| field | value |", "|---|---|"]
    for k, v in [("result", res["result"]), ("engine / ruleset", "%s / %s" % (m["engine"], m["ruleset"])), ("input sha256", m["input_sha256"]), ("input bytes", m["bytes"]), ("input kind", m.get("input_kind", "?")),
                 ("what that means", m.get("structure", "")), ("run time", "%s | %s" % (m["run"]["asia_kuala_lumpur"], m["run"]["utc"])), ("seconds", m.get("duration_s", "?"))]: L.append("| %s | %s |" % (k, v))
    L.append("To reproduce: compute sha256 of the same bytes yourself and compare it with the input sha256 above; re-run the engine and compare fact ids. Compare the engine file hash (selfhash) with the value the template author published outside this computer.")
    if res["result"] not in ("OK", "PARTIAL"): L += ["", "Nothing was assessed: " + esc(res.get("reason", res.get("error", "")), 240)] + not_checked_block(); return "\n".join(L)
    L += ["", "## Components (hash per component)", "| id | kind | bytes | sha256 (first 16) | invisible chars |", "|---|---|---|---|---|"]
    for c in res["components"]: L.append("| %s | %s | %s | %s | %s |" % (data(c["id"], 60), c["kind"], c["size"], c["sha256"][:16], c["invisible_chars"]))
    F = res["facts"]
    def sect(title, label, kinds, cols, row):
        rows = [f for f in F if f["kind"] in kinds]; L.extend(["", "## %s (%d)" % (title, len(rows))])
        if not rows: L.append(zero_line(label)); return
        L.append("| id | level | where | " + " | ".join(cols) + " |"); L.append("|---|---|---|" + "---|" * len(cols))
        for f in rows: L.append("| %s | %s | %s:%s | %s |" % (f["fid"], f["level"], data(f["component"], 50), f["line"], " | ".join(row(f))))
    sect("Plugins listed in the plugins field", "plugin entries", ["plugin", "plugin_launcher"], ["entry", "guess from name (L2h)"], lambda f: [data(f["value"], 50), esc(f.get("class_basis", f["sub"])) + " " + esc(",".join(f.get("name_list_classes", [])))])
    sect("Routines (fields parsed)", "routine entries", ["routine"], ["name", "schedule", "trigger types", "outsiders can influence trigger", "approval wording in text"], lambda f: [data(f["value"], 50), esc(json.dumps(f["schedule"]) + (" (field " + f["schedule_field"] + ")" if f.get("schedule_field") not in (None, "none") else "")), esc(",".join(f["trigger_types"]) or "none"), f["trigger_influenceable_by_outsiders"], f["approval_wording_in_text"]])
    sect("Capability keywords in text and from plugin names", "capability keyword matches", ["capability"], ["class", "basis", "sentence (data)"], lambda f: [f["cls"], esc(f.get("basis", "text keyword")), data(f["quote"], 90)])
    sect("Prohibition wording (negated keyword, clause level)", "prohibition wordings", ["prohibition"], ["class", "sentence (data)"], lambda f: [f["cls"], data(f["quote"], 90)])
    sect("Outside-input channels mentioned", "outside-input channel mentions", ["untrusted_input"], ["channel", "basis"], lambda f: [esc(f["sub"]), esc(f.get("basis", ""))])
    sect("Outbound URLs (exact host from a URL parser; never fetched)", "URLs", ["url"], ["scheme", "exact host", "host kind", "flags"], lambda f: [esc(f.get("scheme", "")), data(f.get("host", f["value"]), 70), f.get("host_kind", "?"), esc(",".join(x for x, y in [("shortener", f.get("shortener")), ("placeholder-in-url", f.get("templated")), ("userinfo-in-url", f.get("userinfo")), ("defanged", f.get("defanged")), ("from decoded text:" + str(f.get("via")), f.get("via"))] if y))])
    sect("Recipients and e-mail addresses (address text withheld; domain only)", "e-mail addresses", ["recipient", "email_address"], ["role", "shown as"], lambda f: [esc(f.get("role", "")), data(f["value"], 60)])
    sect("Hidden or encoded text (decoded text is shown as DATA)", "hidden or encoded text items", ["hidden_text"], ["type", "detail"], lambda f: [esc(f["sub"]), data(f.get("decoded") or f.get("content") or f.get("token") or f["value"], 110) + (" via " + esc(f["via"]) if f.get("via") else "")])
    sect("Secret-shaped strings (masked; value never hashed or stored)", "secret-shaped strings", ["secret"], ["pattern", "masked"], lambda f: [esc(f["sub"]), data(f["value"], 30)])
    sect("Schema and coverage notes", "coverage notes", ["schema"], ["note", "detail"], lambda f: [esc(f["sub"]), data(f["value"], 100)])
    if res["limits_hit"]["truncated_kinds"] or res["limits_hit"]["notes"]: L += ["", "Limits hit: " + esc(json.dumps(res["limits_hit"]), 300) + ". This run is PARTIAL."]
    L += not_checked_block(); return "\n".join(L)

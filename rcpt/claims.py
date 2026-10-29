"""rcpt Claim Check. Reads sentences from a supplied blurb, optionally compares them with the inventory of a supplied template.
Statuses describe the SUPPLIED TEXT only. They never say a claim is true in the world.
 MATCHES_SUPPLIED_TEXT          count claim equals a count the parser found in structured input (exact), nothing more
 CONTRADICTED_BY_SUPPLIED_TEXT  an exact (L2) fact in the supplied text conflicts with the claim; fact ids shown
 NOT_SETTLED                    engine cannot settle it; heuristic (L2h) candidates are listed but never count as refutation
 ASSERTED_NO_EVIDENCE           a statement about checking/safety/superiority/authority with no receipt the engine can read
 PRESSURE_WORDING               wording that asks the reader to skip checking"""
import re, json
from core import *
from lexicon import *
from inventory import inventory

ASSERT_ONLY = {"SAFETY_ASSERT", "VERIFICATION_CLAIM", "SUPERIORITY", "AUTHORITY"}
def vbc_receipt(c, bundle):
    st = c["status"]; asm = {"MATCHES_SUPPLIED_TEXT": "SUPPORTED", "CONTRADICTED_BY_SUPPLIED_TEXT": "REFUTED"}.get(st, "UNRESOLVED")
    return {"schema": "verify-before-claim.receipt.v1", "evaluated_claim": data(c["sentence"], 200), "claim_sha256_12": h12(c["sentence"]), "claim_assessment": asm, "contract_state": "NOT_APPLICABLE",
            "underlying_fact": "KNOWN_FALSE" if asm == "REFUTED" else "UNKNOWN" if asm == "UNRESOLVED" else "NOT_APPLICABLE",
            "provenance_state": "CONTRADICTED" if asm == "REFUTED" and c.get("evidence_kind") == "hash" else "NOT_ESTABLISHED", "external_event_handles": [],
            "evidence_handles": c.get("fids", []), "materialized_artifact": dict(input_sha256=bundle["input_sha256"], bytes=bundle["bytes"]),
            "separation": "UNVERIFIED: the same session produced and judged this run", "limitations": [SCOPE_NOTE, "keyword matching; recall unmeasured on real text"],
            "x_receipt": {"engine": ENGINE_VERSION, "ruleset": RULESET, "status": st, "classes": c["classes"], "origin": c["origin"]}}
def count_of(inv_res, noun):
    n = noun.lower().rstrip("s")
    if n in ("routine", "automation", "schedule", "scheduled task"): return sum(1 for f in inv_res["facts"] if f["kind"] == "routine")
    if n in ("plugin", "connector", "integration"): return sum(1 for f in inv_res["facts"] if f["kind"] == "plugin")
    if n == "skill": return sum(1 for c in inv_res["components"] if c["id"].startswith("skill:") and "/" in c["id"] and c["id"].endswith("/instructions") or False)
    if n == "memorie" or n == "memory": return sum(1 for c in inv_res["components"] if c["kind"] == "memory")
    return None
def eval_absence(s, inv_res):
    F = inv_res["facts"]; structured = inv_res["meta"].get("input_kind") == "json"; low = fold(s).lower(); fids = []; note = ""
    if re.search(r"\b(?:url|link|external|network|internet|outbound|server|remote|third[- ]party|cloud|offline|local[- ]only)", low):
        urls = [f for f in F if f["kind"] == "url" and f.get("scheme") in ("http", "https", "ftp", "ws", "wss")]
        if urls and re.search(r"\b(?:no|zero|without)\s+(?:\w+\s+){0,2}(?:urls?|links?|hosts?)\b", low): return "CONTRADICTED_BY_SUPPLIED_TEXT", [f["fid"] for f in urls[:8]], "the supplied text contains URL(s) (exact parse): %s" % ", ".join(data(f["host"], 40) for f in urls[:4]), "url"
        if urls: return "NOT_SETTLED", [f["fid"] for f in urls[:8]], "the text names hosts %s; naming a host does not show a network call, and this claim is about behaviour" % ", ".join(data(f["host"], 40) for f in urls[:3]), "url"
        note = zero_line("outbound URLs") + " "
    if re.search(r"\bno\s+(?:\w+\s+){0,1}(?:routines?|automations?|schedules?)\b", low) and structured:
        r = [f for f in F if f["kind"] == "routine"]
        if r: return "CONTRADICTED_BY_SUPPLIED_TEXT", [f["fid"] for f in r[:8]], "the structured input lists %d routine entr%s" % (len(r), "y" if len(r) == 1 else "ies"), "structure"
    if re.search(r"\bno\s+(?:\w+\s+){0,1}(?:plugins?|connectors?|integrations?)\b", low) and structured:
        r = [f for f in F if f["kind"] == "plugin"]
        if r: return "CONTRADICTED_BY_SUPPLIED_TEXT", [f["fid"] for f in r[:8]], "the structured input lists %d plugin entr%s" % (len(r), "y" if len(r) == 1 else "ies"), "structure"
    if re.search(r"\bno\s+hidden\b|\bnothing\s+hidden\b", low):
        h = [f for f in F if f["kind"] == "hidden_text" and f["sub"] != "mixed_script"]
        if h: return "CONTRADICTED_BY_SUPPLIED_TEXT", [f["fid"] for f in h[:8]], "the supplied text contains %d hidden or encoded item(s) (exact decode)" % len(h), "hidden"
    mp = re.search(r"\b(send|post|publish|tweet|delete|pay|spend|buy|purchase|execute|run|forward|email|dm|message|share)", low); cl = {"send": "SEND", "forward": "SEND", "email": "SEND", "dm": "SEND", "message": "SEND", "post": "POST", "publish": "POST", "tweet": "POST", "delete": "DELETE", "pay": "PAY", "spend": "PAY", "buy": "PAY", "purchase": "PAY", "execute": "EXEC", "run": "EXEC", "share": "POST"}
    if mp:
        c = cl.get(mp.group(1)); cand = [f for f in F if f["kind"] == "capability" and f["cls"] == c and not f.get("draft_in_sentence")]
        if cand: return "NOT_SETTLED", [f["fid"] for f in cand[:8]], "candidate conflict, NOT a refutation (keyword match, level L2h): the text mentions %s capability at %s" % (c, "; ".join(data(f["quote"], 70) for f in cand[:2])), "capability"
        note += zero_line("matches for the %s capability keyword class" % c) + " "
    return "NOT_SETTLED", fids, (note + "the engine has no exact check for this claim").strip(), "none"

CLAUSE_SPLIT = re.compile(r"\s*;\s*|,\s+|\s+[-\u2013\u2014]\s+|\s+(?:and|but|while|yet|although|though|plus)\s+", re.I)
def _sig(u):
    """claim signature of a piece: its listed classes (REASSURANCE alone does not make a piece stand by itself) plus COUNT when it has a count phrase"""
    sg = {c for c, _ in classes_in(u, uncertain_exempt=True) if c in BLURB_CLASSES and c != "REASSURANCE"}
    if COUNT_RX.search(u): sg.add("COUNT")
    return frozenset(sg)
PER_CLAUSE_EVIDENCE = {"ABSENCE_CAP", "COUNT"}   # these can be settled differently per clause, so same-class neighbours are not joined
def split_claim_clauses(s, inv_res=None):
    """v0.2.1: split a compound sentence into clause-level units so each claim gets its own status.
    Pieces are cut at , ; dash and / and / but / while ... A piece with no claim wording of its own (or only reassurance wording) is joined to the piece before it
    (the first piece: to the piece after it), so 'never sends, posts, or deletes anything' stays one unit. Neighbouring pieces with the same claim classes are joined
    (e.g. 'audited and certified'), except absence and count claims, which are kept apart because each can be settled on its own. Units are exact substrings of the
    sentence. A sentence with fewer than two units, or one that states uncertainty (if / whether / unclear), is returned whole, which is the v0.2.0 behaviour."""
    if UNCERTAIN.search(fold(s)): return [s]
    cuts = [(m.start(), m.end()) for m in CLAUSE_SPLIT.finditer(s)]
    if not cuts: return [s]
    segs = []; prev = 0
    for a, b in cuts: segs.append((prev, a)); prev = b
    segs.append((prev, len(s)))
    groups = []   # [start, end, signature]
    for a, b in segs:
        if not s[a:b].strip(" \t,;"): continue
        sg = _sig(s[a:b])
        if not groups: groups.append([a, b, sg])
        elif sg and not groups[-1][2] and len(groups) == 1: groups[-1][1] = b; groups[-1][2] = sg
        elif sg and sg == groups[-1][2] and not (sg & PER_CLAUSE_EVIDENCE): groups[-1][1] = b
        elif sg and (sg & set(PRESSURE_CLASSES)) and groups[-1][2] and groups[-1][2] <= set(PRESSURE_CLASSES): groups[-1][1] = b; groups[-1][2] = groups[-1][2] | sg   # v0.2.2: a pressure-only piece stays with the pressure wording that follows it
        elif sg: groups.append([a, b, sg])
        else: groups[-1][1] = b
    out = []
    for a, b, sg in groups:
        u = s[a:b].strip(" \t,;"); u = re.sub(r"(?i)^(?:and|but|while|yet|although|though|plus)\s+", "", u).strip()
        if u and _sig(u): out.append(u)
    return out if len(out) >= 2 else [s]

PRESSURE_WHY = {"REQUEST_PRESSURE": "the wording asks the reader to skip checking; it is not evidence about the template",
  "OVERRIDE_PRESSURE": "the wording asks the reader or the bot to set rules aside or skip the checking, or to state an outcome before any check; it is not evidence about the template, and the engine's output does not change because text asks for it",
  "AUTHORITY_CLAIM": "the wording claims to come from, or speak for, a named person or role with authority; the engine cannot see who wrote the text, so the claim is not evidence of its author and gives the text no extra standing"}
def _pressure_rows(ln, s, names):
    rows = []; groups = [[n for n in names if n != "AUTHORITY_CLAIM"], [n for n in names if n == "AUTHORITY_CLAIM"]]
    for g in groups:
        if g: rows.append(dict(line=ln, sentence=s, classes=g, status="PRESSURE_WORDING", fids=[], why=PRESSURE_WHY[g[-1] if "OVERRIDE_PRESSURE" not in g else "OVERRIDE_PRESSURE"], evidence_kind="none", origin="engine-lexicon"))
    return rows
def eval_unit(ln, s, inv_res):
    """status rows for one sentence or clause: a list, empty when it carries no listed claim wording.
    v0.2.2: pressure wording (request / override / authority claim) gets its own PRESSURE_WORDING row(s); any other claim in the same unit still gets its own row."""
    cl = classes_in(s, uncertain_exempt=True); names = [c for c, _ in cl if c in BLURB_CLASSES]
    pn = [n for n in names if n in PRESSURE_CLASSES]
    if pn:
        rows = _pressure_rows(ln, s, pn); rest = [n for n in names if n not in PRESSURE_CLASSES]
        if set(rest) - {"REASSURANCE"}: rows += _eval_claim(ln, s, inv_res, rest)
        return rows
    m = COUNT_RX.search(s)
    if m and inv_res is not None and inv_res["meta"].get("input_kind") == "json":
        w = m.group(1).lower(); n = int(w) if w.isdigit() else WORDNUM.get(w); c = count_of(inv_res, m.group(2))
        if n is not None and c is not None and w != "only":
            ok = (n == c)
            return [dict(line=ln, sentence=s, classes=["COUNT_CLAIM"] + names, status="MATCHES_SUPPLIED_TEXT" if ok else "CONTRADICTED_BY_SUPPLIED_TEXT", fids=[],
                why="parser counted %d %s entries in the structured input; the claim says %s. %s" % (c, esc(m.group(2), 20), n, "A match says nothing about whether this input is the creator's current template." if ok else ""), evidence_kind="count", origin="engine-lexicon")]
    if not names: return []
    return _eval_claim(ln, s, inv_res, names)
def _eval_claim(ln, s, inv_res, names):
    st, fids, why, ek = None, [], "", "none"
    if set(names) & {"ABSENCE_CAP"} and inv_res is not None: st, fids, why, ek = eval_absence(s, inv_res)
    elif set(names) <= ASSERT_ONLY | {"PRIVACY_CLAIM"} and not (set(names) & {"PRIVACY_CLAIM"}): st, why = "ASSERTED_NO_EVIDENCE", "a statement about checking, safety, authority or superiority; no receipt the engine can read was supplied. Ask for: who ran what, on which bytes, when, and a command you can re-run"
    elif "APPROVAL_CLAIM" in names and inv_res is not None:
        ap = [f for f in inv_res["facts"] if f["kind"] == "routine" and f.get("approval_wording_in_text") in ("waived", "mixed")]
        st, fids = "NOT_SETTLED", [f["fid"] for f in ap[:6]]; why = ("candidate conflict, NOT a refutation (wording match, L2h): a routine's text contains wording that waives approval" if ap else "the engine cannot observe approval behaviour at run time; platform approval cards are not visible to it")
    else:
        st = "ASSERTED_NO_EVIDENCE" if set(names) & ASSERT_ONLY else "NOT_SETTLED"
        why = "the engine has no check for this kind of claim; runtime behaviour is not observable from text" if st == "NOT_SETTLED" else "stated without a receipt the engine can read"
    return [dict(line=ln, sentence=s, classes=names, status=st, fids=fids, why=why, evidence_kind=ek, origin="engine-lexicon")]

def claim_check(blurb_bytes, template_bytes=None, model_claims=None, hash_cited=None):
    meta = dict(engine=ENGINE_VERSION, ruleset=RULESET, run=now_stamp(), blurb_sha256=sha(blurb_bytes), blurb_bytes=len(blurb_bytes))
    if len(blurb_bytes) > LIMITS["max_bytes"]: return dict(result="INPUT_TOO_LARGE", meta=meta, claims=[])
    text = blurb_bytes.decode("utf-8", "replace"); inv_res = inventory(template_bytes) if template_bytes is not None else None
    if inv_res is not None and inv_res["result"] not in ("OK", "PARTIAL"): return dict(result=inv_res["result"], reason=inv_res.get("reason", ""), meta=meta, claims=[])
    rows = []; ident = []
    for ln, s in sentences(text)[:400]:
        tick(); hs = HASH_RX.findall(s)
        if hs and inv_res is not None:
            known = {inv_res["meta"]["input_sha256"]} | {c["sha256"] for c in inv_res["components"]} | {c["sha256_normalized"] for c in inv_res["components"]}
            for h in hs:
                ok = h.lower() in known; ident.append((h.lower(), ok))
                if not ok: rows.append(dict(line=ln, sentence=s, classes=["IDENTITY_CLAIM"], status="CONTRADICTED_BY_SUPPLIED_TEXT", fids=[], why="the cited sha256 matches neither the supplied bytes nor any component; the cited receipt does not describe this input", evidence_kind="hash", origin="engine-lexicon"))
        units = split_claim_clauses(s, inv_res)
        if len(units) >= 2:   # compound sentence: one row per clause that carries its own claim
            for i, u in enumerate(units, 1):
                for r in eval_unit(ln, u, inv_res): r["clause"] = "%d/%d" % (i, len(units)); r["sentence_sha256_12"] = h12(s); rows.append(r)
        else: rows += eval_unit(ln, s, inv_res)
    dropped = []
    for q in (model_claims or [])[:50]:
        qs = norm(str(q))
        if len(qs) >= 4 and qs.lower() in norm(text).lower():
            rows.append(dict(line=0, sentence=qs, classes=["MODEL_FOUND"], status="ASSERTED_NO_EVIDENCE", fids=[], why="a claim the model says it found; the model's reading is not a receipt. The engine only confirms the quote is in the supplied text", evidence_kind="none", origin="model-found"))
        else: dropped.append(esc(q, 60))
    rows = rows[:300]
    for r in rows: r["vbc"] = vbc_receipt(r, dict(input_sha256=meta["blurb_sha256"], bytes=meta["blurb_bytes"]))
    return dict(result="OK", meta=meta, claims=rows, identity=ident, dropped_model_claims=dropped, inventory_result=(inv_res["result"] if inv_res else None), inventory_sha256=(inv_res["meta"]["input_sha256"] if inv_res else None))

def render_claims(res):
    m = res["meta"]; L = ["# Receipt report - Claim Check", "Each row says what the SUPPLIED TEXT shows about a sentence. No row says a claim is true or false in the world, and no row gives any mark to the template or the author.", ""]
    L += ["| field | value |", "|---|---|", "| result | %s |" % res["result"], "| engine / ruleset | %s / %s |" % (m["engine"], m["ruleset"]), "| blurb sha256 | %s |" % m["blurb_sha256"], "| template sha256 | %s |" % (res.get("inventory_sha256") or "none supplied"), "| run time | %s | %s |" % (m["run"]["asia_kuala_lumpur"], m["run"]["utc"])]
    if res["result"] != "OK": L += ["", "Nothing was assessed: " + esc(res.get("reason", ""), 200)] + not_checked_block(); return "\n".join(L)
    for h, ok in res.get("identity", []): L.append("Identity: cited sha256 %s %s the supplied bytes or a component of them (identity only; it does not show who ran any check)." % (h[:16], "equals" if ok else "does NOT equal"))
    C = res["claims"]; cnt = lambda s: sum(1 for c in C if c["status"] == s)
    L += ["", "## Sentences and clauses found with listed claim wording (%d)" % len(C)]
    if not C: L.append(zero_line("sentences with listed claim wording"))
    else:
        L += ["| line | sentence (data) | classes | status | evidence ids | why |", "|---|---|---|---|---|---|"]
        for c in C: L.append("| %s | %s | %s | %s | %s | %s |" % (c["line"] if not c.get("clause") else "%s (clause %s)" % (c["line"], c["clause"]), data(c["sentence"], 140), esc(",".join(c["classes"]), 60), c["status"], esc(" ".join(c["fids"][:4]), 60) or "-", esc(c["why"].strip(), 300)))
    if res.get("dropped_model_claims"): L.append("Model-found items dropped because the quote is not in the supplied text: %d." % len(res["dropped_model_claims"]))
    L += ["", "## Bounded result", "- matches_supplied_text: %d" % cnt("MATCHES_SUPPLIED_TEXT"), "- contradicted_by_supplied_text: %d" % cnt("CONTRADICTED_BY_SUPPLIED_TEXT"), "- not_settled: %d" % cnt("NOT_SETTLED"), "- asserted_no_evidence: %d" % cnt("ASSERTED_NO_EVIDENCE"), "- pressure_wording: %d" % cnt("PRESSURE_WORDING"),
          "- provenance: NOT_ESTABLISHED. Hashes, timestamps and this report are not evidence of who ran what.", "- separation: UNVERIFIED. The session that wrote this report also judged it.", "- next action: ask the author for a re-runnable receipt (command, input bytes, tool hash), or run the engine yourself and compare input sha256."]
    L += not_checked_block(); return "\n".join(L)

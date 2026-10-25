# CVE-2026-110264 — regex2shell: Analysis, Detector, Deterministic Kill & Match-Time Write Primitive

Security research on **regex2shell** — the GitLab/Onigmo regex-engine RCE
family disclosed 2026-10-21/23. Primary: **CVE-2026-110264** (CVSS 10.0,
unauthenticated, every GitLab CE/EE since 7.0; found by joaxcar via GitLab's
HackerOne program). Root cause: Onigmo's regex bytecode operands are 16-bit
(`MemNumType`) — more than 32,767 bounded repeats wraps repeat/null-check IDs
negative, driving an OOB **read** in the match-cache count walk and an OOB
**write** at match time. Fixed in GitLab 19.5.1+ and Ruby 4.0.9 / 3.4.12 /
3.3.13. Family context: CVE-2026-89078 (double free), CVE-2026-93577 /
CVE-2026-97229 (compiled-size overflow).

**Results (this repo, all against the pinned lab):** a **safe differential
detector** (zero crashes on both builds), a **deterministic interpreter
kill** (3/3 native `[BUG]` SIGSEGV; the fixed build survives the identical
attack), and a **characterized match-time write primitive** — value and
offset both pattern-controlled, proven with an in-band marker echo — which
goes beyond the public crash-PoCs. The full RCE chain (`system()` as the
server user) remains **open research**: no public technique exists to port
(the reporter's HackerOne writeup is private; public PoCs and labs are
crash/detector/blind-read-oracle artifacts — re-verified 2026-10-24, when
the AumLayer and Flawfence write-ups also stopped short of weaponization).
See [research-writeup](docs/research-writeup.md) §7.

## Verification matrix

| Claim | Evidence |
|---|---|
| Root cause derived from vendor announcements + upstream fix diffs, not blogs | [finding-sheet](docs/finding-sheet.md) (ruby/ruby #16801 / #19020 / #13332; CVE↔bug↔fix table from ruby-lang.org) |
| Differential pair boots: `ruby:3.4.11` (vuln) vs Ruby **3.4.12 compiled from the official tarball** (fixed; hub tag unpublished at build time), org-ruby 0.9.12 pinned, per-request-process render harness | `lab/` + `lab/README.md` — a native `[BUG]` kills one disposable child; `REQUEST_TIMEOUT` models the render-timeout detection |
| The 16-bit boundary, pinned empirically | binary sweep: fixed **accepts 32,767, rejects 32,768** (both ID families: `too many range repeat` / `too many null check`); vuln compiles any N |
| The GitLab org-mode sink reproduced in the lab | `#+TODO:` keyword → `headline.rb` `Regexp.new("^#{keyword}\s*")` — raw interpolation confirmed by the fixed build's error message showing the assembled pattern |
| Safe detector: **VULNERABLE** on 3.4.11 / **NOT-DETECTED** on 3.4.12, zero crashes | `poc/diagnose.py` — org-sink compile oracle + engine compile-only corroboration + benign control; 3/3+3/3 each way, exit 0/1 |
| Deterministic kill: `[BUG]` SIGSEGV at `re.match` (N=100000, ID-aliasing zone ≥65536), harness alive | `poc/crash.py` — 3/3 kills; fixed build survives identical attack 3/3 (clean `RegexpError`) |
| The #19020 sibling arm: compile-time unroll hang | `(?:.{90000,}){90000}` → 15s TIMEOUT on vuln vs 89ms clean compile on fixed |
| Match-time write primitive, characterized | `exploit/echo.py` + gdb autopsy: 8-byte write at `repeat_stk[id]` (regexec.c:3846), **value = repeat index + δ, offset = wrapped id × 8**; deterministic in-process marker echo (`marker[2938]+832 = 0x800e`); impossible-nested pair disables the count walk → pure write |

## Quick start

```bash
# differential pair: Ruby 3.4.11 (:29565) + 3.4.12-from-source (:29566)
cd lab && docker compose up -d --build && cd ..   # fixed side compiles ~10 min once

python3 poc/diagnose.py --port 29565          # VULNERABLE (exit 0)
python3 poc/diagnose.py --port 29566          # NOT-DETECTED (exit 1)

python3 poc/crash.py --rounds 3 --check-fixed # 3/3 [BUG] kills; fixed survives

python3 exploit/echo.py --port 29565          # write-primitive probe (echo landing
                                               # through the harness is layout-dependent)
```

Everything Ruby-side runs inside Docker; the host only needs Python 3
(stdlib) and Docker.

## Documents

| Doc | What it is |
|---|---|
| [docs/finding-sheet.md](docs/finding-sheet.md) | One-page datasheet: versions, CVSS, the family map (4 GitLab CVEs = 3 Onigmo bugs = 3 upstream fixes), sink chain, detection signatures (TLDR Sigma), traps |
| [docs/report-ptes.md](docs/report-ptes.md) | PTES-structured report (7 phases) with lab evidence |
| [docs/research-writeup.md](docs/research-writeup.md) | The investigation narrative — patch-first method, sink traps, primitive characterization, what is proven vs open |

## What is original here vs prior work

The vulnerabilities, their discovery and the exploitation designs are
**prior work by joaxcar** (Johan Carlsson, via GitLab's HackerOne program;
the full report remains restricted — public at 90 days post-patch),
GitLab (disclosure, patch, TLDR detections) and the Ruby core team (upstream
fixes). yaamlabs published the mechanics outline (16-bit wrap, `#+TODO:`
interpolation, request-body grooming → `system()`); public PoC repos
(TahuCryptsi et al.) are crash/detector scripts — equivalent to this repo's
`poc/` layer; the deepest public artifact, the lesterlam reproduction lab,
compiles the engine standalone and demonstrates a blind-read oracle at the
same primitive characterized below — but explicitly excludes weaponized RCE
(re-verified 2026-10-23 and 2026-10-24: no public technique exists to port).
GitLab itself calls the real attack "a grind": noisy, most attempts failing
— consistent with the heap-layout dependence measured in this repo's lab.

Original work in this repo: the **fix-commit-anchored family datasheet**
(ruby/ruby PR diffs), the **dockerized Ruby+org-ruby differential pair**
(3.4.12 built from the official tarball while the image tag was
unpublished), the **safe org-sink oracle** (compile-time divergence, zero
crashes), the **empirical 2¹⁵ boundary pinning**, the
**impossible-nested count-walk bypass** (pure write without the OOB read),
the **write-primitive characterization** (value = repeat index + δ, offset =
wrapped id × 8, both pattern-controlled), the **glibc dynamic-threshold
grooming discovery** (engine arrays land on the brk heap among Ruby
objects), and the **in-band marker echo** proving the controlled write. As
with the companion repos, no real-world target is ever touched — the lab
images, harness and proof scripts are all purpose-built.

## Repository layout

```
docs/     finding-sheet · report-ptes · research-writeup
poc/      diagnose.py (safe oracle) · crash.py (deterministic kill)
exploit/  echo.py (write-primitive probe + groom harness support)
lab/      differential compose pair + per-request-process Ruby harness
odd/      feature tracking document
```

## References

- Advisories: [GitLab 19.5.1 patch release](https://docs.gitlab.com/releases/patches/patch-release-gitlab-19-5-1-released/) · [GHSA-83vq-rvff-66gw](https://github.com/advisories/GHSA-83vq-rvff-66gw) · [ruby-lang.org regexp fixes](https://www.ruby-lang.org/en/news/2026/10/23/regexp-fixes-for-gitlab-cves/)
- Upstream fixes: [ruby/ruby#16801](https://github.com/ruby/ruby/pull/16801) · [#19020](https://github.com/ruby/ruby/pull/19020) · [#13332](https://github.com/ruby/ruby/pull/13332)
- Detections: [TLDR onigmo_native_worker_crash](https://gitlab.com/gitlab-security-oss/tldr/-/blob/main/Detections/platforms/GitLab/Vulnerability%20Detections/onigmo_native_worker_crash.md) · [org_mode_render_error_burst](https://gitlab.com/gitlab-security-oss/tldr/-/blob/main/Detections/platforms/GitLab/Vulnerability%20Detections/org_mode_render_error_burst.md)
- Third-party: [yaamlabs analysis](https://yaamlabs.com/blog/gitlab-cve-2026-110264-regex-compiler) · [al-ice.ai gem analysis](https://al-ice.ai/posts/2026/10/gitlab-cve-2026-110264-org-ruby-headline-regexp-unpatched-gem/) · [TahuCryptsi crash PoC](https://exploit-intel.com/exploit/5191822114207195) (prior art for the detector layer) · [lesterlam reproduction lab](https://sploitus.com/exploit?id=ECD80861-9EF6-5241-B99B-0FC4F2E238AD) · [AumLayer lab analysis](https://aumlayer.com/research/gitlab-org-mode-regex-overflow/) (GitLab CE 19.3.5 vs 19.3.6) · [Flawfence writeup](https://flawfence.com/blog/en/gitlab-cve-2026-110264-unauthenticated-rce-onigmo/)

# PTES report — regex2shell / CVE-2026-110264 (+ family)

Penetration Testing Execution Standard structure, scoped to the local lab
pair defined in `lab/README.md`. No real-world target was touched at any
point.

## 1. Scope and planning

| Item | Value |
|---|---|
| Target | Local differential pair: `ruby:3.4.11` (vulnerable) vs Ruby 3.4.12 built from the official release tarball (fixed), each + org-ruby 0.9.12 |
| Delivered as | Per-request-process HTTP harness (`/render`, `/re`, `/version`, `/src`) modeling the GitLab render path |
| Vulnerability class | Integer overflow → memory corruption (CWE-190/787) in Onigmo regex compilation/matching |
| Primary CVE | CVE-2026-110264 (CVSS 10.0, AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H) |
| Authorizations | Repo owner's lab only; anonymous-network delivery modeled in-lab |

## 2. Information gathering

- Vendor sources pinned first: ruby-lang.org fix news (CVE↔bug↔PR↔version
  table), GitLab 19.5.1 patch notes, TLDR Sigma detections, upstream fix
  diffs (ruby/ruby #16801 / #19020 / #13332).
- Sink chain derived from org-ruby 0.9.12 source (read from inside the
  container): `parser.rb#store_in_buffer_setting` escapes `#+TODO:`
  keywords into `custom_keyword_regexp`; `headline.rb#parse_keywords` then
  interpolates the **raw** keyword into `Regexp.new("^#{@keyword}\s*")`.
- Third-party outlines (yaamlabs) used as leads and re-verified in-lab.

## 3. Vulnerability analysis

- **Root cause** (`docs/finding-sheet.md`): bytecode operands are 16-bit
  `MemNumType`; >32,767 bounded repeats wrap repeat/null-check IDs negative
  at compile; the match-cache count walk reads `repeat_range[id].lower` OOB
  (regexec.c:403) and `match_at` writes `repeat_stk[mem]` OOB (regexec.c:3846).
- **Boundary pinned empirically**: fixed accepts 32,767, rejects 32,768
  (both ID families); vuln compiles any N.
- **Two payload traps discovered**: `parser.rb` strips parenthetical notes
  (`gsub!(/\(.*\)/, "")`) → sink payloads must be paren-free; small
  quantifiers (`a{0,1}`) are inlined — only larger bounded repeats
  (`a{0,100}`) emit `OP_REPEAT` and participate in the ID space.

## 4. Exploitation (lab)

| Step | Tool | Result |
|---|---|---|
| Safe detection | `poc/diagnose.py` | org-sink oracle: vuln renders the malicious `.org` (3028 ms) vs fixed `RegexpError: too many range repeat` with the interpolated pattern in the message; engine compile-only corroboration; controls pass; zero crashes on both builds |
| Deterministic DoS/kill | `poc/crash.py` | N=100000 match → 3/3 native `[BUG]` SIGSEGV inside `re.match`; harness serves the next request normally; fixed build rejects at compile and survives 3/3 |
| Sibling arm (#19020) | probe P10 | `(?:.{90000,}){90000}` hangs compilation on vuln (killed at 15 s) vs 89 ms clean compile on fixed |
| Write primitive | `exploit/echo.py` + gdb | 8-byte write at `repeat_stk[id]`: **value = repeat index + δ** (attacker-chosen k), **offset = wrapped id × 8**; impossible-nested pair placed first in the pattern aborts the count walk (`goto impossible`) leaving the pure write; deterministic in-process marker echo (`marker[2938]+832 = 0x800e`); glibc dynamic-threshold discovery places the engine arrays on the brk heap among Ruby objects |

## 5. Post-exploitation assessment

- Match outcomes are heap-layout dependent: the corrupted-ID walk segfaults
  9/9 in a minimal child, survives 9/9 inside the allocation-churned
  org-render child — consistent with the reporter's request-body heap
  grooming outline.
- Full RCE (`system()` as the server user) **not reproduced**: no public
  technique exists to port; the chain (deterministic adjacency of the
  260 KiB `repeat_stk` buffer to a controlled victim, then escalation) is
  documented as open research in `docs/research-writeup.md` §7.

## 6. Risk assessment

- Every self-managed GitLab CE/EE from 7.0 (2014) to the 2026-10-21 fixes;
  unauthenticated via any public project's `.org` file (anonymous view
  triggers the render), plus an authenticated blob-preview route.
- Re-patch trap: instances patched on 2026-10-12 (CVE-2026-97229, versions
  19.2.8/19.3.5/19.4.2) remain vulnerable — the new fixes sit exactly one
  patch above.
- Beyond GitLab: any application compiling attacker-controlled regexp
  source (`Regexp.new`, `Regexp.union`, interpolation). `Regexp.timeout`
  and pattern-length limits do **not** reliably protect (some triggers are
  short; the timeout does not guard compilation).

## 7. Remediation

- Upgrade GitLab to 19.5.1 / 19.4.3 / 19.3.6 (or backports 19.2.9 / 19.1.9 /
  19.0.10 / 18.11.13) and Ruby to 4.0.9 / 3.4.12 / 3.3.13.
- Never compile regexes from untrusted input; treat untrusted-pattern
  compilation as unsupported.
- Detect: TLDR Sigma `onigmo_native_worker_crash` (match-time shape ⇒
  CVE-2026-110264) and `org_mode_render_error_burst`; this repo's
  `poc/diagnose.py` provides a safe build-level oracle for inventory.

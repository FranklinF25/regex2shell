# Finding sheet — CVE-2026-110264 + family: GitLab/Onigmo regex RCEs

One-page datasheet. Root cause derived from the vendor announcements and the
upstream fix diffs (ruby/ruby PRs #13332, #19020, #16801), not from blogs.
Blog/3rd-party claims used only where marked and re-verified in the lab.

## At a glance (primary: CVE-2026-110264)

| Field | Value |
|---|---|
| CVSS | **10.0** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` |
| Class | Integer overflow → memory corruption → unauthenticated RCE |
| Component | Onigmo (Ruby's built-in regex engine), bundled inside GitLab |
| Trigger | Compiling+matching a specially crafted regexp from user input |
| GitLab sink | Org-mode renderer: `.org` file → org-ruby 0.9.12 → `Regexp.new` with interpolated `#+TODO:` keyword |
| Auth | None — anonymous visitor viewing a public project's `.org` file (2nd route: blob editor preview, authenticated) [yaamlabs, unverified] |
| Affected | **Every GitLab CE/EE since 7.0 (2014)** |
| Fixed (GitLab) | 19.5.1, 19.4.3, 19.3.6 + backports 19.2.9, 19.1.9, 19.0.10, 18.11.13 (2026-10-21) |
| Fixed (Ruby) | 4.0.9 / 3.4.12 / 3.3.13 (2026-10-23) |
| Reporter | joaxcar (Johan Carlsson) via GitLab's HackerOne program (H1 #4093475, still restricted; refs also GitLab work item 633633) |
| In the wild | No known exploitation; **not in CISA KEV as of 2026-10-24**. CISA SSVC "Attend" (Exploitation none / Automatable yes / Technical impact total); EPSS ~1% (42nd pct). NVD + cve.org records live since 2026-10-21/22 (CWE-190) |

## Family map — 4 GitLab CVEs = 3 Onigmo bugs = 3 upstream fixes

Authoritative mapping: ruby-lang.org news 2026-10-23 ("Regexp compilation
fixes related to GitLab's CVEs"). C files live upstream in ruby/Onigmo.

| GitLab CVE | CVSS / auth | GitLab fix | Onigmo bug | Upstream fix | Ruby 4.0 | Ruby 3.4 | Ruby 3.3 |
|---|---|---|---|---|---|---|---|
| CVE-2026-89078 | 9.9 / authed | 19.4.1 | Double free when parsing fails after an alternation | ruby/ruby#13332 (regparse.c: free node once via temp pointer) | 4.0.0 | **3.4.12** | 3.3.13 |
| CVE-2026-93577 | 9.9 / authed | 19.4.1 | Integer overflow in the **size of a compiled pattern** | ruby/ruby#19020 commits `c2a3805` + `b3095b7` (regcomp.c) | 4.0.8 | **3.4.12** | 3.3.13 |
| CVE-2026-97229 | 10.0 / unauth (CI lint path) | 19.4.2 (2026-10-12) | same size-overflow bug, CI/CD `regexp_matcher.rb` path | same as 93577 | 4.0.8 | **3.4.12** | 3.3.13 |
| **CVE-2026-110264** | **10.0 / unauth** | **19.5.1** | **Overflow of internal repeat/null-check IDs in a pattern with many repeats** | **ruby/ruby#16801** commit `493d26dc` (regcomp.c, +20/−0) | 4.0.9 | **3.4.12** | 3.3.13 |

All three fixes land together in Ruby 3.4.12 → the lab pair is
`ruby:3.4.11` (vulnerable to all three) vs `ruby:3.4.12` (fixed).
GitLab's own backports of the Ruby fixes are public as omnibus patches:
`config/patches/ruby/regexp-repeat-id-overflow-{3.3,3.4,4.0}.patch`
(omnibus-gitlab commit `73cec6d8`) — a second primary diff source alongside
the ruby/ruby PRs.

## Primary bug mechanics (CVE-2026-110264 = PR #16801)

Onigmo's compiler numbers every bounded repeat and every empty-check with an
internal counter, emitted into the compiled program as a `MemNumType`
(16-bit field; the exact wrap boundary is pinned empirically in this repo's
lab). A pattern with more repeats than the field can hold wraps the counter:

* `compile_range_repeat_node()` — emits the `OP_REPEAT` instruction with
  `reg->num_repeat` as its ID, then increments. On overflow the emitted ID is
  a wrapped value.
* `compile_tree_empty_check()` — same for `OP_EMPTY_CHECK` / null-check IDs
  (`reg->num_null_check`).
* At **match time**, `OP_REPEAT`/`OP_REPEAT_INC` index the engine's
  repeat-stack with that ID — the wrapped/negative index writes out of
  bounds while the pattern is being *matched*, not compiled. This is why the
  TLDR crash signature for this CVE is match-time (`match_at` /
  `onig_search_gpos` frames), unlike the CI-path CVEs whose signature is
  compile-time (`onig_compile`/`compile_tree`).

The fix (diff verbatim, +2 lines in regcomp.c):

```c
  r = add_mem_num(reg, reg->num_null_check); /* NULL CHECK ID */
  if (r) return r;
  reg->num_null_check++;
+ if ((MemNumType)reg->num_null_check <= 0) return ONIGERR_TOO_MANY_NULL_CHECK;
```
```c
  r = add_mem_num(reg, num_repeat); /* OP_REPEAT ID */
  reg->num_repeat++;
+ if ((MemNumType)reg->num_repeat <= 0) return ONIGERR_TOO_MANY_RANGE_REPEAT;
```

plus two new error codes in `include/ruby/onigmo.h`
(`ONIGERR_TOO_MANY_RANGE_REPEAT` -224, `ONIGERR_TOO_MANY_NULL_CHECK` -225)
and their messages in `regerror.c` ("too many range repeat" / "too many
null check").

Upstream regression tests (`test/ruby/test_regexp.rb`):

```ruby
source = '(?:foobar){0,100}' * 100000          # too many range repeats
assert_raise(RegexpError) { Regexp.new(source) }
source = '(?:(?:foo)?|(?:bar)?)*' * 100000     # too many null checks
assert_raise(RegexpError) { Regexp.new(source) }
```

## Secondary bugs (lab-relevant, same pair)

* **#19020 compiled-size overflow** — `(?:.{90000,}){90000}`: the int
  product `tlen * qn->lower` overflows, so the inline-unroll limit check
  passes for an enormous repeat (`Regexp.new` hangs unrolling it);
  `.{100000,}` × 21475: emitted program size passes `INT_MAX`, wrapping
  `RelAddrType` offsets. Fix: limit compare by division (`c2a3805`); cap
  program size as emitted → `RegexpError` (`b3095b7`).
* **#13332 double free** — parse failure after an alternation with too-big
  repetition quantifiers freed the node twice (parse-time + compile-time).

## Sink chain (GitLab)

```
.org file (public project, anonymous view)
  → Banzai/HTML pipeline → OtherMarkupFilter (Timeout-wrapped)
  → org-ruby 0.9.12 headline.rb: first pattern escapes the #+TODO: keyword,
    a second Regexp.new interpolates the raw keyword → attacker controls
    regexp source                                [yaamlabs; verified in lab]
  → Onigmo compile (ID assignment) + match (OOB via wrapped ID)
  → heap grooming via request body → system() as the `git` user   [yaamlabs]
```

CI route of the family (CVE-2026-97229): unauthenticated `/ci/lint`
`regexp_matcher.rb` → same engine, compile-time signature.

## Detections (GitLab TLDR, Sigma)

* **onigmo_native_worker_crash** (id `58461d1f-…657f`, critical,
  puma_stderr.log): `[BUG]` **and** (org-ruby frames `headline.rb` /
  `regexp_helper.rb` **or** Onigmo frames `match_at`/`onig_search_gpos`/
  `onig_compile`/`compile_tree`/`compile_length_tree`/`rb_str_sub_bang`).
  Match-time shape ⇒ CVE-2026-110264; compile-time shape ⇒ CI CVEs.
* **org_mode_render_error_burst** (exceptions_json.log): single client ≥ 5
  `Timeout::Error` from the `OtherMarkup` renderer on `.org` files within
  30 min — the rendering-campaign signature of 110264.
* Response guidance: treat as attempted RCE; join by host+time; pull `.org`
  payloads and `#+TODO:` lines; hunt `/tmp` files owned by `git`, child
  processes, outbound conns; rotate `gitlab-secrets.json`/tokens on success.

## Traps and reach

* **Re-patch trap**: 19.2.8 / 19.3.5 / 19.4.2 (2026-10-12, fixed
  CVE-2026-97229) are one patch **below** the 110264 fixes (19.2.9 /
  19.3.6 / 19.4.3) → instances patched on 10-12 remain vulnerable.
* **Ruby-side traps**: 3.2 and earlier get **no fix** (3.2 EOL 2026-04-01,
  3.2.11 was final — move to 3.4/4.0); 4.0.8 (same week) fixed the
  size-overflow pair but **not** 110264 — 4.0 users must install 4.0.9.
  Tracker timeline (bugs.ruby-lang.org, via WebProNews 2026-10-23): the
  #16801 fix sat on **master since April 2026** (first lands in Ruby 4.1);
  S. Kaag flagged 4.0.8 shipping without it, J. Boussier (byroot) backported
  to 3.4/3.3 within hours. Master-only merges ahead of a backport release
  leave maintenance branches silently exposed — same lesson as the GitLab
  re-patch trap.
* **CVE-scanner gap**: GitLab's CVE records name only GitLab as the affected
  product, so scanners matching CVE records against installed Ruby versions
  have nothing to match — inventory via `ruby -v` or this repo's detector.
* **Embedded Ruby**: GitLab Omnibus ships its own interpreter — check
  `/opt/gitlab/embedded/bin/ruby -v`; patching the distro Ruby does nothing
  for GitLab, and GitLab's patch does nothing for other Ruby apps.
* Reach beyond GitLab: any app that compiles attacker-controlled regexp
  source (`Regexp.new`, `Regexp.union`, `Regexp.compile`, `/#{input}/`
  interpolation). `Regexp.timeout` does **not** protect; pattern-length
  limits do not reliably protect (some triggers are short).
* Ruby requested no CVEs of its own (so far); track via GitLab's CVE ids
  (precedents: CVE-2022-28738, CVE-2024-27282).

## Lab anchors

Differential pair `ruby:3.4.11` vs `ruby:3.4.12`, org-ruby pinned 0.9.12,
per-request-process render harness (a `[BUG]` kills one disposable worker,
mirroring Puma worker respawn). Details + probe tables: `lab/README.md`.

## References

- ruby-lang.org/en/news/2026/10/23/regexp-fixes-for-gitlab-cves/ (CVE↔bug↔fix table, credits)
- NVD nvd.nist.gov/vuln/detail/CVE-2026-110264 · cve.org CVE record (published 2026-10-21/22, CWE-190, CISA ADP SSVC)
- gitlab.com/gitlab-org/omnibus-gitlab commit 73cec6d8 — GitLab's public Ruby backport patches (regexp-repeat-id-overflow-{3.3,3.4,4.0}.patch)
- docs.gitlab.com/releases/patches/patch-release-gitlab-19-5-1-released/ (CVSS 10.0, affected ranges, detections)
- github.com/ruby/ruby/pull/16801 · /pull/19020 · /pull/13332 (fix diffs)
- gitlab.com/gitlab-security-oss/tldr — onigmo_native_worker_crash.md · org_mode_render_error_burst.md
- yaamlabs.com/blog/gitlab-cve-2026-110264-regex-compiler (3rd-party mechanics: 16-bit ID, `#+TODO:` interpolation, `system()` as `git`)
- thehackernews.com/2026/10/ruby-fixes-three-regex-engine-bugs.html (Ruby-side remediation facts: 3.2 EOL no-fix, 4.0.8 partial-fix trap, CVE-scanner gap, embedded-Ruby check)
- GHSA-83vq-rvff-66gw (GitLab advisory record)

# regex2shell lab — differential pair

Two Ruby containers built around **org-ruby 0.9.12** (the gem GitLab's
Org-mode renderer uses), one vulnerable, one fixed. Everything Ruby-side
runs inside Docker; the host only needs Python 3 (stdlib) and Docker.

| Service | Image | Port | Role |
|---|---|---|---|
| `regex2shell-vuln` | `ruby:3.4.11` + org-ruby 0.9.12 | **29565** | vulnerable — pre ruby/ruby#13332/#19020/#16801 |
| `regex2shell-fixed` | Ruby **3.4.12 compiled from the official tarball** + org-ruby 0.9.12 | **29566** | fixed — first release with all three Onigmo fixes |

Why the fixed side is source-built: Ruby 3.4.12 was released 2026-10-23 but
the official docker-library tag was not published yet at build time; the
Dockerfile compiles `cache.ruby-lang.org/pub/ruby/3.4/ruby-3.4.12.tar.gz`
in a builder stage (the `ruby:3.4.11` base provides the toolchain) and
guards with `ruby -v | grep 'ruby 3.4.12'`. Swap back to the official image
when the tag exists.

## Why one process per request

Every request is rendered by a **disposable child process**: a native Onigmo
`[BUG]` aborts only that child — mirroring a Puma worker crash + respawn —
while the harness stays up and reports a structured verdict. Requests over
`REQUEST_TIMEOUT` (15 s) are killed and reported `TIMEOUT`, the lab analog of
the GitLab OtherMarkup render timeout that the `org_mode_render_error_burst`
detection watches.

Routes (all JSON):

| Route | What it does |
|---|---|
| `POST /render` | body = raw `.org` content → org-ruby render in a child (the GitLab sink path) |
| `POST /re` | body = `{pattern, match, subject}` → `Regexp.new` (+ optional match) in a child (engine-level probe) |
| `GET /version` | ruby + org-ruby versions |
| `GET /src?path=` | org-ruby gem source, read-only (sink verification) |

Verdicts: `OK` (exit 0) · `REGEXP_ERROR` (exit 3 — clean `RegexpError`/`SyntaxError` rejection) ·
`CRASH` (killed by signal; `bug=true` when stderr shows `[BUG]`) · `TIMEOUT` · `ERROR`.

## Empirical findings this lab was built on

All numbers from this exact pair (fresh child per request; `N` = number of
repeated quantifier units in the pattern source).

| # | Probe | vuln 3.4.11 | fixed 3.4.12 |
|---|---|---|---|
| P1 | benign `.org` render (`* Hello` + emphasis + link) | OK, identical HTML, ~80 ms | OK, identical HTML |
| P2 | compile-only `(?:foobar){0,100}` × 100000 | **OK — compiled** (52 ms; the corrupted program exists) | `REGEXP_ERROR: too many range repeat` |
| P3 | compile-only `(?:(?:foo)?\|(?:bar)?)*` × 100000 | OK — compiled (134 ms) | `REGEXP_ERROR: too many null check` |
| P4 | boundary sweep, both families | compiles OK at N = 32768 / 32769 / 100000 | **accepts ≤ 32767, rejects ≥ 32768** (= 2¹⁵ → `MemNumType` behaves as signed 16-bit) |
| P5 | **org sink**: `#+TODO: a{0,100}×33000` + headline keyword | **OK — rendered** (3028 ms; sink compiles the corrupted regex, `sub!` walk lands benign) | `REGEXP_ERROR: too many range repeat: /^a{0,100}a{0,100}…` (message shows the interpolated sink pattern) |
| P5ctl | same shape × 100 (control) | OK | OK |
| P6 | org sink crash attempt × 65536 and × 100000 | OK 3/3 + 3/3 (~3.2 s walk) | `REGEXP_ERROR` |
| P7 | `a{0,1}` × 65536 (inlined quantifier) | OK | OK — no `OP_REPEAT` emitted → no ID assigned → nothing to reject |
| P8 | engine **match**, N sweep | 32768/32769/40000 → OK (one flaky match-time `RegexpError` seen at 32769); **65536 / 70000 / 100000 → CRASH SIGSEGV `[BUG]` at `re.match`** (100000: 3/3) | `REGEXP_ERROR` (never compiled) |
| P9 | match-shape isolation at N = 100000 | **CRASH 4/4**: group body × (`foobar`×6 / empty subject), char body × (`a`×300 / empty), and the exact sink shape `^a{0,100}…\s*` vs the literal keyword text (anchored + unanchored) | — |
| P10 | `(?:.{90000,}){90000}` (the #19020 unroll arm) | **TIMEOUT** — compile hangs unrolling, killed at 15 s | OK, 89 ms (limit compared by division → no unroll) |

Harness survives every crash; a benign render right after a kill is served
normally (post-crash health checks OK throughout).

### Mechanism notes

* **The 32768 boundary (2¹⁵)**: the compiler's repeat/null-check counters are
  emitted as `MemNumType` (16-bit). IDs ≥ 32768 wrap **negative**; IDs ≥ 65536
  wrap back to **positive and collide with live IDs** — the aliasing zone is
  what makes N ≥ 65536 a deterministic kill at match time, while the
  negative-only zone (32768–65535) corrupts benignly or flakily.
* **Match outcome is heap-layout dependent**: the same corrupted regex,
  matched in a minimal child (P8/P9), segfaults 9/9; matched inside the
  org-render child — after the parser's allocation churn — the OOB stack
  writes land benign (P6, 9/9 OK). The real-world exploit drives exactly
  this with request-body heap grooming (yaamlabs); turning the bare
  corruption into a *controlled* write is this repo's exploit work.
* **The sink chain** (org-ruby 0.9.12, verbatim):
  * `parser.rb#store_in_buffer_setting` — `#+TODO:` keywords are
    `Regexp.escape`d into `custom_keyword_regexp` (first pattern: safe), but
  * `headline.rb#parse_keywords` — after `words[0]` matches, the **raw**
    keyword goes to `Regexp.new("^#{@keyword}\s*")` (second pattern:
    attacker-controlled regexp source). Confirmed empirically: a keyword
    `(unclosed` yields `RegexpError: end pattern with unmatched parenthesis:
    /^(unclosed */` on both builds — the interpolation itself.
* **Two payload traps**: `parser.rb` runs `keyword.gsub!(/\(.*\)/, "")`
  ("parenthetical notes") so sink payloads must be **paren-free**; and
  small quantifiers like `a{0,1}` are inlined (no `OP_REPEAT`, no ID) — only
  larger bounded repeats like `a{0,100}` participate in the ID space.

## Usage

```bash
docker compose up -d --build     # fixed side compiles Ruby (~10 min first build)

curl -s http://127.0.0.1:29565/version   # vuln probe
curl -s http://127.0.0.1:29566/version   # fixed probe
```

## Teardown

```bash
docker compose down
```

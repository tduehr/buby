#!/usr/bin/env ruby
# notice... we're using MRI ruby here, not JRuby (but either will work)

require 'drb'

unless drb_uri = ARGV.shift
  STDERR.puts "Usage: #{File.basename $0} druby://<addr>:<port>"
  exit 1
end

drb = DRbObject.new nil, drb_uri
rsp=drb.make_http_request 'example.com', 80, false, "GET / HTTP/1.0\r\n\r\n"

puts rsp

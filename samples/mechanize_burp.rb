#!/usr/bin/env jruby

require 'rubygems'
require 'buby'
require 'mechanize'
require 'rbkb/http'
require 'irb'

include Java

# This Buby handler implementation simply keeps cookie state synched
# for a Mechanize agent by intercepting all requests sent through the
# Burp proxy. This lets you use Mechanize in tandem with your browser
# through Burp without having to fuss around with cookies.
module MechGlue
  attr_accessor :mech_agent

  def evt_proxy_message(*param)
    msg_ref, is_req, rhost, rport, is_https, http_meth, url, 
    resourceType, status, req_content_type, message, action = param

    if (not is_req) and (message =~ /Set-Cookie/i)

      rsp = Rbkb::Http::Response.new(message, :ignore_content_length => true)

      # Get an uri object ready for mechanize
      uri = URI.parse(url)
      uri.scheme = (is_https)? "https" : "http"
      uri.host = rhost
      uri.port = rport
      
      # Grab cookies from headers:
      rsp.headers.get_header_value('Set-Cookie').each do |cookie| 
        WWW::Mechanize::Cookie.parse(uri, cookie) do |c|
          @mech_agent.cookie_jar.add(uri, c)
        end
      end
    end
    return(message)
  end
end


if __FILE__ == $0
  $mech = WWW::Mechanize.new
  #$mech.set_proxy('localhost', '8080')

  $burp = Buby.new()
  $burp.extend(MechGlue)
  $burp.mech_agent = $mech
  $burp.start_burp

  puts "$burp is set to #{$burp.class}"
  puts "$mech is set to #{$mech.class}"
  IRB.start
end


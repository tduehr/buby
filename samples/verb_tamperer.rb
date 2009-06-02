#!/usr/bin/env jruby
require 'rubygems'
require 'buby'

class VerbTamperer < Buby
  def evt_proxy_message(*param)
    msg_ref, is_req, rhost, rport, is_https, http_meth, url, 
    resourceType, status, req_content_type, message, action = param

    if is_req and http_meth == "GET"
      message[0,3] = "PET"
      action[0] = Buby::ACTION_DONT_INTERCEPT

      return super(*param).dup
    else
      return super(*param)
    end
  end
end

VerbTamperer.start_burp()

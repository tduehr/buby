#!/usr/bin/env jruby
$: << File.join(File.dirname(__FILE__), %w[.. lib])

require 'buby'
$DEBUG = true
Buby.load_burp("/path/to/burp.jar") if not Buby.burp_loaded?
buby = Buby.start_burp()

require 'net/http'
p = Net::HTTP::Proxy("localhost", 8080).start("www.google.com")

# Note: I'm using 'instance_eval' here only to stay with the flow of the 
# existing IRB session. Normally, you'd probably want to implement this as 
# an override in your Buby-derived class.

buby.instance_eval do

  def evt_proxy_message(*param)
    msg_ref, is_req, rhost, rport, is_https, http_meth, url, resourceType, 
    status, req_content_type, message, action = param

    if is_req and http_meth=="GET"
      # Change the HTTP request verb to something silly
      message[0,3] = "PET"

      # Forcibly disable interception in the Burp UI
      action[0] = Buby::ACTION_DONT_INTERCEPT

      # Return a new instance and still get $DEBUG info
      return super(*param).dup
    else
      # Just get $DEBUG info for all other requests
      return super(*param)
    end
  end

end

# Now, make another request using the Net::HTTP client
p.get("/")



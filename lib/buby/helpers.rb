
require 'uri'

class Buby
  module HttpRequestResponseHelper

    # returns the response as a Ruby String object - returns an empty string
    # if response is nil.
    def response_str
      return response().nil? ? "" : ::String.from_java_bytes(response())
    end
    alias response_string response_str
    alias rsp_str response_str

    def response_headers
      if headers=(@rsp_split ||= rsp_str.split(/\r?\n\r?\n/, 2))[0]
        @rsp_headers ||= headers.split(/\r?\n/).map {|h| h.split(/\s*:\s*/,2)}
      end
    end

    def response_body
      (@rsp_split ||= rsp_str.split(/\r?\n\r?\n/, 2))[1]
    end

    # returns the request as a Ruby String - returns an empty string if 
    # request is nil.
    def request_str
      return request().nil? ? "" : ::String.from_java_bytes(request())
    end
    alias request_string request_str
    alias req_str request_str

    def request_headers
      if headers=(@req_split ||= req_str.split(/\r?\n\r?\n/, 2))[0]
        @req_headers ||= headers.split(/\r?\n/).map {|h| h.split(/\s*:\s*/,2)}
      end
    end
    alias req_headers request_headers

    def request_body
      (@req_split ||= req_str.split(/\r?\n\r?\n/, 2))[1]
    end
    alias req_body request_body

    # Returns a Ruby URI object derived from the java.net.URL object
    def uri
      @uri ||= URI.parse url.to_s if not url.nil?
    end

    # one-shot method to implant ourselves onto a target object's class
    # interface in ruby. All later instances will also get 'us' for free!
    def self.implant(base)
      return if @implanted
      base.class.instance_eval { include(self) }
      @implanted = true
    end

    def self.implanted? ; @implanted; end
  end

  
  module ScanIssue
    # Returns a Ruby URI object derived from the java.net.URL object
    def uri
      @uri ||= URI.parse url.to_s if not url.nil?
    end

    # one-shot method to implant ourselves onto a target object's class
    # interface in ruby. All later instances will also get 'us' for free!
    def self.implant(base)
      return if @implanted
      base.class.instance_eval { include(self) }
      @implanted = true
    end

    def self.implanted? ; @implanted; end
  end
end

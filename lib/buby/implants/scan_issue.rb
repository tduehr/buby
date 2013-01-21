require 'uri'

class Buby
  class ScanIssuesList < BubyArrayWrapper
    def initialize(obj)
      ScanIssueHelper.implant(obj[0]) if obj.size > 0 
      super(obj)
    end
  end

  # @deprecated this will change to the new style in the next release
  module ScanIssueHelper
    # Returns a Ruby URI object derived from the java.net.URL object
    def uri
      @uri ||= URI.parse url.to_s if not url.nil?
    end

    # one-shot method to implant ourselves onto a target object's class
    # interface in ruby. All later instances will also get 'us' for free!
    def self.implant(base)
      return if @implanted
      base.class.instance_eval { include(ScanIssueHelper) }
      @implanted = true
    end

    def http_messages
      HttpRequestResponseList.new( self.getHttpMessages() )
    end
    alias messages http_messages
    alias messages http_messages

    def self.implanted? ; @implanted; end
  end
end


require 'uri'

class Buby
  # This interface is used to retrieve details of Scanner issues. Extensions can
  # obtain details of issues by registering an +IScannerListener+ or by calling
  # {Buby#getScanIssues}. Extensions can also add custom Scanner issues by
  # registering an +IScannerCheck+ or calling {Buby#addScanIssue}, and providing
  # their own implementations of this interface
  #
  class ScanIssue
    include Java::Burp::IScanIssue

    attr_accessor :uri, :name, :type, :severity, :confidence, :ibackground
    attr_accessor :rbackground, :idetail, :rdetail, :messages, :service

    # @param [Hash] hash
    def initialize hash
      @uri = hash[:uri].kind_of?(URI) ? hash[:uri] : hash[:uri].to_s
      @name = hash[:name]
      @type = hash[:type]
      @severity = hash[:severity]
      @confidence = hash[:confidence]
      @ibackground = hash[:ibackground]
      @rbackground = hash[:rbackground]
      @idetail = hash[:idetail]
      @rdetail = hash[:rdetail]
      @messages = hash[:messages]
      @service = hash[:service]
    end

    # This method returns the URL for which the issue was generated.
    #
    # @return [Java::JavaNet::URL] The URL for which the issue was generated.
    #
    def getUrl; Java::JavaNet::URL.new @uri.to_s; end

    # This method returns the name of the issue type.
    #
    # @return [String] The name of the issue type (e.g. "SQL injection").
    #
    def getIssueName; @name; end

    # This method returns a numeric identifier of the issue type. See the Burp
    # Scanner help documentation for a listing of all the issue types.
    #
    # @return [Fixnum] A numeric identifier of the issue type.
    #
    def getIssueType; @type; end

    # This method returns the issue severity level.
    #
    # @return [String] The issue severity level. Expected values are "High",
    #   "Medium", "Low", "Information" or "False positive".
    #
    #
    def getSeverity; @severity; end

    # This method returns the issue confidence level.
    #
    # @return [String] The issue confidence level. Expected values are
    #   "Certain", "Firm" or "Tentative".
    #
    def getConfidence; @confidence; end

    # This method returns a background description for this type of issue.
    #
    # @return [String] A background description for this type of issue, or +nil+
    #   if none applies.
    #
    def getIssueBackground; @ibackground; end

    # This method returns a background description of the remediation for this
    # type of issue.
    #
    # @return [String] A background description of the remediation for this type
    #   of issue, or +nil+ if none applies.
    #
    def getRemediationBackground; @rbackground; end

    # This method returns detailed information about this specific instance of
    # the issue.
    #
    # @return [String] Detailed information about this specific instance of the
    #   issue, or +nil+ if none applies.
    #
    def getIssueDetail; @idetail; end

    # This method returns detailed information about the remediation for this
    # specific instance of the issue.
    #
    # @return Detailed information about the remediation for this specific
    #   instance of the issue, or +nil+ if none applies.
    #
    def getRemediationDetail; @rdetail; end

    # This method returns the HTTP messages on the basis of which the issue was
    # generated.
    #
    # @return The HTTP messages on the basis of which the issue was generated.
    # @note The items in this array should be instances of
    #   +IHttpRequestResponseWithMarkers+ if applicable, so that details of the
    #   relevant portions of the request and response messages are available.
    #
    def getHttpMessages; @messages; end

    # This method returns the HTTP service for which the issue was generated.
    #
    # @return The HTTP service for which the issue was generated.
    #
    def getHttpService; @service; end
  end
end
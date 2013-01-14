class Buby
  # Extensions can implement this interface and then call
  # {Buby#registerHttpListener} to register an HTTP listener. The listener will
  # be notified of requests and responses made by any Burp tool. Extensions can
  # perform custom analysis or modification of these messages by registering an
  # HTTP listener.
  # 
  class HttpListener
    # This method is invoked when an HTTP request is about to be issued, and
    # when an HTTP response has been received.
    #
    # @param [Fixnum, Symbol] toolFlag A flag indicating the Burp tool that
    #   issued the request. Burp tool flags are defined in the
    #   +IBurpExtenderCallbacks+ interface and {Buby}.
    # @param [Boolean] messageIsRequest Flags whether the method is being
    #   invoked for a request or response.
    # @param [IHttpRequestResponse] messageInfo Details of the request/response
    #   to be processed. Extensions can call the setter methods on this object
    #   to update the current message and so modify Burp's behavior.
    #
    # @todo move HttpRequestResponse to new implant scheme
    def processHttpMessage(toolFlag, messageIsRequest, messageInfo)
      pp [:got_processHttpMessage, toolFlag, messageIsRequest, messageInfo] if $DEBUG
      Buby::HttpRequestResponseHelper.implant(messageInfo)
    end
  end
end
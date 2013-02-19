class Buby

  # Extensions can implement this interface and then call
  # {Buby#registerScannerInsertionPointProvider} to register a factory for
  # custom Scanner insertion points.
  #
  class ScannerInsertionPointProvider
    include Java::Burp::IScannerInsertionPointProvider

    # When a request is actively scanned, the Scanner will invoke this method,
    # and the provider should provide a list of custom insertion points that
    # will be used in the scan.
    # @note these insertion points are used in addition to those that are
    #   derived from Burp Scanner's configuration, and those provided by any
    #   other Burp extensions.
    #
    # @param [IHttpRequestResponse] baseRequestResponse The base request that will be actively scanned.
    # @return [Array<IScannerInsertionPoint>, nil] A list of
    #   +IScannerInsertionPoint+ objects that should be used in thescanning, or
    #   +nil+ if no custom insertion points are applicable for this request.
    #
    def getInsertionPoints(baseRequestResponse)
      pp [:got_getInsertionPoints, baseRequestResponse] if $DEBUG
      __getInsertionPoints(baseRequestResponse).tap{|x|Buby::HttpRequestResponseHelper.implant(x)}
    end
  end
end

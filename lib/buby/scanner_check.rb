class Buby
  # Extensions can implement this interface and then call
  # {Buby#registerScannerCheck} to register a custom Scanner check. When
  # performing scanning, Burp will ask the check to perform active or passive
  # scanning on the base request, and report any Scanner issues that are
  # identified.
  #
  # @todo DSL methods
  class ScannerCheck
    include Java::Burp::IScannerCheck

    REPORT_EXISTING = -1
    REPORT_BOTH     =  0
    REPORT_NEW      =  1
    
    # The Scanner invokes this method for each base request / response that is
    # passively scanned.
    # @note Extensions should not only analyze the HTTP messages provided during
    #   passive scanning, and should not make any new HTTP requests of their
    #   own.
    #
    # @param [IHttpRequestResponse] baseRequestResponse The base HTTP request /
    #   response that should be passively scanned.
    # @return [Array<IScanIssue>, nil] A list of +IScanIssue+ objects, or +nil+
    #   if no issues are identified.
    #
    # @abstract subclass and call +super+
    def doPassiveScan(baseRequestResponse)
      pp [:got_doPassiveScan, baseRequestResponse] if $DEBUG
      Buby::HttpRequestResponseHelper.implant baseRequestResponse
      nil
    end

    # The Scanner invokes this method for each insertion point that is actively
    # scanned. Extensions may issue HTTP requests as required to carry out
    # active scanning, and should use the +IScannerInsertionPoint+ object
    # provided to build scan requests for particular payloads.
    # @note Extensions are responsible for ensuring that attack payloads are
    #   suitably encoded within requests (for example, by URL-encoding relevant
    #   metacharacters in the URL query string). Encoding is not automatically
    #   carried out by the +IScannerInsertionPoint+, because this would prevent
    #   Scanner checks from testing for certain input filter bypasses.
    #   Extensions should query the +IScannerInsertionPoint+ to determine its
    #   type, and apply any encoding that may be appropriate.
    #
    # @param [IHttpRequestResponse] baseRequestResponse The base HTTP request /
    #   response that should be actively scanned.
    # @param [IScannerInsertionPoint] insertionPoint An object that can be
    #   queried to obtain details of the insertion point being tested, and can
    #   be used to build scan requests for particular payloads.
    # @return [Array<IScanIssue>, nil] A list of +IScanIssue+ objects, or +nil+ if no
    #   issues are identified.
    #
    # @abstract subclass and call +super+
    def doActiveScan(baseRequestResponse, insertionPoint)
      pp [:got_doActiveScan, baseRequestResponse, insertionPoint] if $DEBUG
      Buby::HttpRequestResponseHelper.implant baseRequestResponse
      Buby::Implants::ScannerInsertionPoint.implant insertionPoint
      nil
    end

    # The Scanner invokes this method when the custom Scanner check has
    # reported multiple issues for the same URL path. This can arise either
    # because there are multiple distinct vulnerabilities, or because the same
    # (or a similar) request has been scanned more than once. The custom check
    # should determine whether the issues are duplicates. In most cases, where
    # a check uses distinct issue names or descriptions for distinct issues,
    # the consolidation process will simply be a matter of comparing these
    # features for the two issues.
    #
    # @param [IScanIssue] existingIssue An issue that was previously reported by this Scanner check.
    # @param [IScanIssue] newIssue An issue at the same URL path that has been newly reported by this Scanner check.
    # @return An indication of which issue(s) should be reported in the main Scanner results. The method should return
    #   * {REPORT_EXISTING} to report the existing issue only,
    #   * {REPORT_BOTH} to report both issues, and
    #   * {REPORT_NEW} to report the new issue only.
    #
    # @abstract subclass and override to proccess scan issues
    def consolidateDuplicateIssues(existingIssue, newIssue)
      pp [:got_consolidateDuplicateIssues, existingIssue, newIssue]
      REPORT_BOTH
    end
  end
end

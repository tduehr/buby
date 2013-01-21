class Buby
  # Extensions can implement this interface and then call
  # {Buby#registerScannerListener} to register a Scanner listener. The listener
  # will be notified of new issues that are reported by the Scanner tool.
  # Extensions can perform custom analysis or logging of Scanner issues by
  # registering a Scanner listener.
  #
  class ScannerListener
    include Java::Burp::IScannerListener
    # This method is invoked when a new issue is added to Burp Scanner's
    # results.
    #
    # @param [IScanIssue] issue An object that the extension can query to obtain
    #   details about the new issue.
    #
    # @abstract
    def newScanIssue(issue)
      pp [:got_newScanIssue, issue] if $DEBUG
      Buby::ScanIssueHelper.implant issue
    end
  end
end
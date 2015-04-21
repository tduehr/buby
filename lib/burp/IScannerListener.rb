# @!parse
#   module Burp
#     # Extensions can implement this interface and then call
#     # {IBurpExtenderCallbacks#registerScannerListener} to register a Scanner
#     # listener. The listener will be notified of new issues that are reported
#     # by the Scanner tool. Extensions can perform custom analysis or logging
#     # of Scanner issues by registering a Scanner listener.
#     #
#     module IScannerListener
#       # This method is invoked when a new issue is added to Burp Scanner's
#       # results.
#       #
#       # @param [IScanIssue] issue An {IScanIssue} object that the extension
#       #   can query to obtain details about the new issue.
#       #
#       # @return [void]
#       #
#       def newScanIssue(issue); end
#       alias new_scan_issue newScanIssue
#     end
#   end

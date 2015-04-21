# @!parse
#   module Burp
#     # Extensions can implement this interface and then call
#     # {IBurpExtenderCallbacks#registerScannerCheck} to register a custom
#     # Scanner check. When performing scanning, Burp will ask the check to
#     # perform active or passive scanning on the base request, and report any
#     # Scanner issues that are identified.
#     #
#     module IScannerCheck
#       # The Scanner invokes this method for each base request / response that
#       # is passively scanned.
#       #
#       # @note Extensions should only analyze the HTTP messages provided
#       #   during passive scanning, and should not make any new HTTP requests
#       #   of their own.
#       # @param [IHttpRequestResponse] baseRequestResponse The base HTTP
#       #   request / response that should be passively scanned.
#       #
#       # @return [Array<IScanIssue>] A list of {IScanIssue} objects, or +nil+
#       #   if no issues are identified.
#       #
#       def doPassiveScan(baseRequestResponse); end
#       alias do_passive_scan doPassiveScan
#
#       # The Scanner invokes this method for each insertion point that is
#       # actively scanned. Extensions may issue HTTP requests as required to
#       # carry out active scanning, and should use the
#       # {IScannerInsertionPoint} object provided to build scan requests for
#       # particular payloads.
#       #
#       # @note Scan checks should submit raw non-encoded payloads to insertion
#       #   points, and the insertion point has responsibility for performing
#       #   any data encoding that is necessary given the nature and location
#       #   of the insertion point.
#       # @param [IHttpRequestResponse] baseRequestResponse The base HTTP
#       #   request / response that should be actively scanned.
#       # @param [IScannerInsertionPoint] insertionPoint An
#       #   {IScannerInsertionPoint} object that can be queried to obtain
#       #   details of the insertion point being tested, and can be used to
#       #   build scan requests for particular payloads.
#       #
#       # @return [Array<IScanIssue>] A list of {IScanIssue} objects, or +nil+
#       #   if no issues are identified.
#       #
#       def doActiveScan(baseRequestResponse, insertionPoint); end
#       alias do_active_scan doActiveScan
#
#       # The Scanner invokes this method when the custom Scanner check has
#       # reported multiple issues for the same URL path. This can arise either
#       # because there are multiple distinct vulnerabilities, or because the
#       # same (or a similar) request has been scanned more than once. The
#       # custom check should determine whether the issues are duplicates. In
#       # most cases, where a check uses distinct issue names or descriptions
#       # for distinct issues, the consolidation process will simply be a
#       # matter of comparing these features for the two issues.
#       #
#       # @param [IScanIssue] existingIssue An issue that was previously
#       #   reported by this Scanner check.
#       # @param [IScanIssue] newIssue An issue at the same URL path that has
#       #   been newly reported by this Scanner check.
#       #
#       # @return [int] An indication of which issue(s) should be reported in
#       #   the main Scanner results. The method should return <code>-1</code>
#       #   to report the existing issue only, +0+ to report both issues, and
#       #   +1+ to report the new issue only.
#       #
#       def consolidateDuplicateIssues(existingIssue, newIssue); end
#       alias consolidate_duplicate_issues consolidateDuplicateIssues
#     end
#   end

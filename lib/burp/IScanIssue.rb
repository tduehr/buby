# @!parse
#   module Burp
#     # This interface is used to retrieve details of Scanner issues.
#     # Extensions can obtain details of issues by registering an
#     # {IScannerListener} or by calling
#     # {IBurpExtenderCallbacks#getScanIssues}.
#     #
#     # Extensions can also add custom Scanner issues by registering an
#     # {IScannerCheck} or calling {IBurpExtenderCallbacks#addScanIssue}, and
#     # providing their own implementations of this interface
#     #
#     module IScanIssue
#       # This method returns the URL for which the issue was generated.
#       #
#       # @return [java.net.URL] The URL for which the issue was generated.
#       #
#       def getUrl; end
#       alias get_url getUrl
#       alias url getUrl
#
#       # This method returns the name of the issue type.
#       #
#       # @return [String] The name of the issue type (e.g. "SQL injection").
#       #
#       def getIssueName; end
#       alias get_issue_name getIssueName
#       alias issue_name getIssueName
#
#       # This method returns a numeric identifier of the issue type. See the
#       # Burp Scanner help documentation for a listing of all the issue types.
#       #
#       # @return [int] A numeric identifier of the issue type.
#       #
#       def getIssueType; end
#       alias get_issue_type getIssueType
#       alias issue_type getIssueType
#
#       # This method returns the issue severity level.
#       #
#       # @return [String] The issue severity level. Expected values are
#       #   "High", "Medium", "Low", "Information" or "False positive".
#       #
#       #
#       def getSeverity; end
#       alias get_severity getSeverity
#       alias severity getSeverity
#
#       # This method returns the issue confidence level.
#       #
#       # @return [String] The issue confidence level. Expected values are
#       #   "Certain", "Firm" or "Tentative".
#       #
#       def getConfidence; end
#       alias get_confidence getConfidence
#       alias confidence getConfidence
#
#       # This method returns a background description for this type of issue.
#       #
#       # @return [String] A background description for this type of issue, or
#       #   +nil+ if none applies.
#       #
#       def getIssueBackground; end
#       alias get_issue_background getIssueBackground
#       alias issue_background getIssueBackground
#
#       # This method returns a background description of the remediation for
#       # this type of issue.
#       #
#       # @return [String] A background description of the remediation for this
#       #   type of issue, or +nil+ if none applies.
#       #
#       def getRemediationBackground; end
#       alias get_remediation_background getRemediationBackground
#       alias remediation_background getRemediationBackground
#
#       # This method returns detailed information about this specific instance
#       # of the issue.
#       #
#       # @return [String] Detailed information about this specific instance of
#       #   the issue, or +nil+ if none applies.
#       #
#       def getIssueDetail; end
#       alias get_issue_detail getIssueDetail
#       alias issue_detail getIssueDetail
#
#       # This method returns detailed information about the remediation for
#       # this specific instance of the issue.
#       #
#       # @return [String] Detailed information about the remediation for this
#       #   specific instance of the issue, or +nil+ if none applies.
#       #
#       def getRemediationDetail; end
#       alias get_remediation_detail getRemediationDetail
#       alias remediation_detail getRemediationDetail
#
#       # This method returns the HTTP messages on the basis of which the issue
#       # was generated.
#       #
#       # @return [Array<IHttpRequestResponse>] The HTTP messages on the basis
#       #   of which the issue was generated.
#       # @note The items in this array should be instances of
#       #   {IHttpRequestResponseWithMarkers} if applicable, so that details of
#       #   the relevant portions of the request and response messages are
#       #   available.
#       #
#       def getHttpMessages; end
#       alias get_http_messages getHttpMessages
#       alias http_messages getHttpMessages
#
#       # This method returns the HTTP service for which the issue was
#       # generated.
#       #
#       # @return [IHttpService] The HTTP service for which the issue was
#       #   generated.
#       #
#       def getHttpService; end
#       alias get_http_service getHttpService
#       alias http_service getHttpService
#     end
#   end

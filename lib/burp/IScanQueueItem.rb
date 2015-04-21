# @!parse
#   module Burp
#     # This interface is used to retrieve details of items in the Burp Scanner
#     # active scan queue.
#     #
#     # Extensions can obtain references to scan queue items by calling
#     # {IBurpExtenderCallbacks#doActiveScan}.
#     #
#     module IScanQueueItem
#       # This method returns a description of the status of the scan queue
#       # item.
#       #
#       # @return [String] A description of the status of the scan queue item.
#       #
#       def getStatus; end
#       alias get_status getStatus
#       alias status getStatus
#
#       # This method returns an indication of the percentage completed for the
#       # scan queue item.
#       #
#       # @return [byte] An indication of the percentage completed for the scan
#       #   queue item.
#       #
#       def getPercentageComplete; end
#       alias get_percentage_complete getPercentageComplete
#       alias percentage_complete getPercentageComplete
#
#       # This method returns the number of requests that have been made for
#       # the scan queue item.
#       #
#       # @return [int] The number of requests that have been made for the scan
#       #   queue item.
#       #
#       def getNumRequests; end
#       alias get_num_requests getNumRequests
#       alias num_requests getNumRequests
#
#       # This method returns the number of network errors that have occurred
#       # for the scan queue item.
#       #
#       # @return [int] The number of network errors that have occurred for the
#       #   scan queue item.
#       #
#       def getNumErrors; end
#       alias get_num_errors getNumErrors
#       alias num_errors getNumErrors
#
#       # This method returns the number of attack insertion points being used
#       # for the scan queue item.
#       #
#       # @return [int] The number of attack insertion points being used for
#       #   the scan queue item.
#       #
#       def getNumInsertionPoints; end
#       alias get_num_insertion_points getNumInsertionPoints
#       alias num_insertion_points getNumInsertionPoints
#
#       # This method allows the scan queue item to be canceled.
#       #
#       # @return [void]
#       #
#       def cancel; end
#
#       # This method returns details of the issues generated for the scan
#       # queue item.
#       #
#       # @note different items within the scan queue may contain duplicated
#       #   versions of the same issues - for example, if the same request has
#       #   been scanned multiple times. Duplicated issues are consolidated in
#       #   the main view of scan results. Extensions can register an
#       #   {IScannerListener} to get details only of unique, newly discovered
#       #   Scanner issues post-consolidation.
#       #
#       # @return [Array<IScanIssue>] Details of the issues generated for the
#       #   scan queue item.
#       #
#       def getIssues; end
#       alias get_issues getIssues
#       alias issues getIssues
#     end
#   end

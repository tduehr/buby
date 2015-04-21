# @!parse
#   module Burp
#     # Extensions can implement this interface and then call
#     # {IBurpExtenderCallbacks#registerScannerInsertionPointProvider} to
#     # register a factory for custom Scanner insertion points.
#     #
#     module IScannerInsertionPointProvider
#       # When a request is actively scanned, the Scanner will invoke this
#       # method, and the provider should provide a list of custom insertion
#       # points that will be used in the scan.
#       #
#       # @note these insertion points are used in addition to those that are
#       #   derived from Burp Scanner's configuration, and those provided by
#       #   any other Burp extensions.
#       #
#       # @param [IHttpRequestResponse] baseRequestResponse The base request
#       #   that will be actively scanned.
#       #
#       # @return [Array<IScannerInsertionPoint>] A list of
#       #   {IScannerInsertionPoint} objects that should be used in the
#       #   scanning, or +nil+ if no custom insertion points are applicable for
#       #   this request.
#       #
#       def getInsertionPoints(baseRequestResponse); end
#       alias get_insertion_points getInsertionPoints
#       alias insertion_points getInsertionPoints
#     end
#   end

# @!parse
#   module Burp
#     # This interface is used for an {IHttpRequestResponse} object that has
#     # had markers applied.
#     #
#     # Extensions can create instances of this interface using
#     # {IBurpExtenderCallbacks#applyMarkers}, or provide their own
#     # implementation. Markers are used in various situations, such as
#     # specifying Intruder payload positions, Scanner insertion points, and
#     # highlights in Scanner issues.
#     #
#     module IHttpRequestResponseWithMarkers
#       include IHttpRequestResponse
#
#       # This method returns the details of the request markers.
#       #
#       # @return [Array<Array<int>>] A list of index pairs representing the
#       #   offsets of markers for the request message. Each item in the list
#       #   is an +int[2]+ array containing the start and end offsets for the
#       #   marker. The method may return +nil+ if no request markers are
#       #   defined.
#       #
#       def getRequestMarkers; end
#       alias get_request_markers getRequestMarkers
#       alias request_markers getRequestMarkers
#
#       # This method returns the details of the response markers.
#       #
#       # @return [Array<Array<int>>] A list of index pairs representing the
#       #   offsets of markers for the response message. Each item in the list
#       #   is an +int[2]+ array containing the start and end offsets for the
#       #   marker. The method may return +nil+ if no response markers are
#       #   defined.
#       #
#       def getResponseMarkers; end
#       alias get_response_markers getResponseMarkers
#       alias response_markers getResponseMarkers
#     end
#   end

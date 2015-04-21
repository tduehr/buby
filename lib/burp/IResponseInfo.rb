# @!parse
#   module Burp
#     # This interface is used to retrieve key details about an HTTP response.
#     #
#     # Extensions can obtain an {IResponseInfo} object for a given response by
#     # calling {IExtensionHelpers#analyzeResponse}.
#     #
#     module IResponseInfo
#       # This method is used to obtain the HTTP headers contained in the
#       # response.
#       #
#       # @return [Array<String>] The HTTP headers contained in the response.
#       #
#       def getHeaders; end
#       alias get_headers getHeaders
#       alias headers getHeaders
#
#       # This method is used to obtain the offset within the response where
#       # the message body begins.
#       #
#       # @return [int] The offset within the response where the message body
#       #   begins.
#       #
#       def getBodyOffset; end
#       alias get_body_offset getBodyOffset
#       alias body_offset getBodyOffset
#
#       # This method is used to obtain the HTTP status code contained in the
#       # response.
#       #
#       # @return [short] The HTTP status code contained in the response.
#       #
#       def getStatusCode; end
#       alias get_status_code getStatusCode
#       alias status_code getStatusCode
#
#       # This method is used to obtain details of the HTTP cookies set in the
#       # response.
#       #
#       # @return [Array<ICookie>] A list of {ICookie} objects representing the
#       #   cookies set in the response, if any.
#       #
#       def getCookies; end
#       alias get_cookies getCookies
#       alias cookies getCookies
#
#       # This method is used to obtain the MIME type of the response, as
#       # stated in the HTTP headers.
#       #
#       # @return [String] A textual label for the stated MIME type, or an
#       #   empty String if this is not known or recognized. The possible
#       #   labels are the same as those used in the main Burp UI.
#       #
#       def getStatedMimeType; end
#       alias get_stated_mime_type getStatedMimeType
#       alias stated_mime_type getStatedMimeType
#
#       # This method is used to obtain the MIME type of the response, as
#       # inferred from the contents of the HTTP message body.
#       #
#       # @return [String] A textual label for the inferred MIME type, or an
#       #   empty String if this is not known or recognized. The possible
#       #   labels are the same as those used in the main Burp UI.
#       #
#       def getInferredMimeType; end
#       alias get_inferred_mime_type getInferredMimeType
#       alias inferred_mime_type getInferredMimeType
#     end
#   end

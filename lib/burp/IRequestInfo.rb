# @!parse
#   module Burp
#     # This interface is used to retrieve key details about an HTTP request.
#     #
#     # Extensions can obtain an {IRequestInfo} object for a given request by
#     # calling {IExtensionHelpers#analyzeRequest}.
#     #
#     module IRequestInfo
#
#       # Used to indicate that there is no content.
#       #
#       # # CONTENT_TYPE_NONE = 0;
#
#       # Used to indicate URL-encoded content.
#       #
#       # # CONTENT_TYPE_URL_ENCODED = 1;
#
#       # Used to indicate multi-part content.
#       #
#       # # CONTENT_TYPE_MULTIPART = 2;
#
#       # Used to indicate XML content.
#       #
#       # # CONTENT_TYPE_XML = 3;
#
#       # Used to indicate JSON content.
#       #
#       # # CONTENT_TYPE_JSON = 4;
#
#       # Used to indicate AMF content.
#       #
#       # # CONTENT_TYPE_AMF = 5;
#
#       # Used to indicate unknown content.
#       #
#       # # CONTENT_TYPE_UNKNOWN = -1;
#
#       # This method is used to obtain the HTTP method used in the request.
#       #
#       # @return [String] The HTTP method used in the request.
#       #
#       def getMethod; end
#       alias get_method getMethod
#       alias method getMethod
#
#       # This method is used to obtain the URL in the request.
#       #
#       # @return [URL] The URL in the request.
#       #
#       def getUrl; end
#       alias get_url getUrl
#       alias url getUrl
#
#       # This method is used to obtain the HTTP headers contained in the
#       # request.
#       #
#       # @return [Array<String>] The HTTP headers contained in the request.
#       #
#       def getHeaders; end
#       alias get_headers getHeaders
#       alias headers getHeaders
#
#       # This method is used to obtain the parameters contained in the
#       # request.
#       #
#       # @return [Array<IParameter>] The parameters contained in the request.
#       #
#       def getParameters; end
#       alias get_parameters getParameters
#       alias parameters getParameters
#
#       # This method is used to obtain the offset within the request where the
#       # message body begins.
#       #
#       # @return [int] The offset within the request where the message body
#       #   begins.
#       #
#       def getBodyOffset; end
#       alias get_body_offset getBodyOffset
#       alias body_offset getBodyOffset
#
#       # This method is used to obtain the content type of the message body.
#       #
#       # @return [byte] An indication of the content type of the message body.
#       #   Available types are defined within this interface.
#       #
#       def getContentType; end
#       alias get_content_type getContentType
#       alias content_type getContentType
#     end
#   end

# @!parse
#   module Burp
#     # This interface contains a number of helper methods, which extensions
#     # can use to assist with various common tasks that arise for Burp
#     # extensions.
#     #
#     # Extensions can call {IBurpExtenderCallbacks#getHelpers} to obtain an
#     # instance of this interface.
#     #
#     module IExtensionHelpers
#       # This method can be used to analyze an HTTP request, and obtain
#       # various key details about it.
#       #
#       # @param [IHttpRequestResponse] request An {IHttpRequestResponse}
#       #   object containing the request to be analyzed.
#       #
#       # @return [IRequestInfo] An {IRequestInfo} object that can be queried
#       #   to obtain details about the request.
#       #
#       def analyzeRequest(request); end
#       alias analyze_request analyzeRequest
#
#       # This method can be used to analyze an HTTP request, and obtain
#       # various key details about it.
#       #
#       # @param [IHttpService] httpService The HTTP service associated with
#       #   the request. This is optional and may be +nil+, in which case the
#       #   resulting {IRequestInfo} object will not include the full request
#       #   URL.
#       # @param [byte[]] request The request to be analyzed.
#       #
#       # @return [IRequestInfo] An {IRequestInfo} object that can be queried
#       #   to obtain details about the request.
#       #
#       def analyzeRequest(httpService, request); end
#       alias analyze_request analyzeRequest
#
#       # This method can be used to analyze an HTTP request, and obtain
#       # various key details about it. The resulting {IRequestInfo} object
#       # will not include the full request URL. To obtain the full URL, use
#       # one of the other overloaded {analyzeRequest} methods.
#       #
#       # @param [byte[]] request The request to be analyzed.
#       #
#       # @return [IRequestInfo] An {IRequestInfo} object that can be queried
#       #   to obtain details about the request.
#       #
#       def analyzeRequest(request); end
#       alias analyze_request analyzeRequest
#
#       # This method can be used to analyze an HTTP response, and obtain
#       # various key details about it.
#       #
#       # @param [byte[]] response The response to be analyzed.
#       #
#       # @return [IResponseInfo] An {IResponseInfo} object that can be queried
#       #   to obtain details about the response.
#       #
#       def analyzeResponse(response); end
#       alias analyze_response analyzeResponse
#
#       # This method can be used to retrieve details of a specified parameter
#       # within an HTTP request.
#       #
#       # @note Use {analyzeRequest} to obtain details of all parameters within
#       #   the request.
#       # @param [byte[]] request The request to be inspected for the specified
#       #   parameter.
#       # @param [String] parameterName The name of the parameter to retrieve.
#       #
#       # @return [IParameter] An {IParameter} object that can be queried to
#       #   obtain details about the parameter, or +nil+ if the parameter was
#       #   not found.
#       #
#       def getRequestParameter(request, parameterName); end
#       alias get_request_parameter getRequestParameter
#       alias request_parameter getRequestParameter
#
#       # This method can be used to URL-decode the specified data.
#       #
#       # @param [String] data The data to be decoded.
#       #
#       # @return [String] The decoded data.
#       #
#       def urlDecode(data); end
#       alias url_decode urlDecode
#
#       # This method can be used to URL-encode the specified data. Any
#       # characters that do not need to be encoded within HTTP requests are
#       # not encoded.
#       #
#       # @param [String] data The data to be encoded.
#       #
#       # @return [String] The encoded data.
#       #
#       def urlEncode(data); end
#       alias url_encode urlEncode
#
#       # This method can be used to URL-decode the specified data.
#       #
#       # @param [byte[]] data The data to be decoded.
#       #
#       # @return [byte[]] The decoded data.
#       #
#       def urlDecode(data); end
#       alias url_decode urlDecode
#
#       # This method can be used to URL-encode the specified data. Any
#       # characters that do not need to be encoded within HTTP requests are
#       # not encoded.
#       #
#       # @param [byte[]] data The data to be encoded.
#       #
#       # @return [byte[]] The encoded data.
#       #
#       def urlEncode(data); end
#       alias url_encode urlEncode
#
#       # This method can be used to Base64-decode the specified data.
#       #
#       # @param [String] data The data to be decoded.
#       #
#       # @return [byte[]] The decoded data.
#       #
#       def base64Decode(data); end
#       alias base64_decode base64Decode
#
#       # This method can be used to Base64-decode the specified data.
#       #
#       # @param [byte[]] data The data to be decoded.
#       #
#       # @return [byte[]] The decoded data.
#       #
#       def base64Decode(data); end
#       alias base64_decode base64Decode
#
#       # This method can be used to Base64-encode the specified data.
#       #
#       # @param [String] data The data to be encoded.
#       #
#       # @return [String] The encoded data.
#       #
#       def base64Encode(data); end
#       alias base64_encode base64Encode
#
#       # This method can be used to Base64-encode the specified data.
#       #
#       # @param [byte[]] data The data to be encoded.
#       #
#       # @return [String] The encoded data.
#       #
#       def base64Encode(data); end
#       alias base64_encode base64Encode
#
#       # This method can be used to convert data from String form into an
#       # array of bytes. The conversion does not reflect any particular
#       # character set, and a character with the hex representation 0xWXYZ
#       # will always be converted into a byte with the representation 0xYZ. It
#       # performs the opposite conversion to the method {bytesToString}, and
#       # byte-based data that is converted to a String and back again using
#       # these two methods is guaranteed to retain its integrity (which may
#       # not be the case with conversions that reflect a given character set).
#       #
#       # @param [String] data The data to be converted.
#       #
#       # @return [byte[]] The converted data.
#       #
#       def stringToBytes(data); end
#       alias string_to_bytes stringToBytes
#
#       # This method can be used to convert data from an array of bytes into
#       # String form. The conversion does not reflect any particular character
#       # set, and a byte with the representation 0xYZ will always be converted
#       # into a character with the hex representation 0x00YZ. It performs the
#       # opposite conversion to the method {stringToBytes}, and byte-based
#       # data that is converted to a String and back again using these two
#       # methods is guaranteed to retain its integrity (which may not be the
#       # case with conversions that reflect a given character set).
#       #
#       # @param [byte[]] data The data to be converted.
#       #
#       # @return [String] The converted data.
#       #
#       def bytesToString(data); end
#       alias bytes_to_string bytesToString
#
#       # This method searches a piece of data for the first occurrence of a
#       # specified pattern. It works on byte-based data in a way that is
#       # similar to the way the native Java method {String.indexOf()} works on
#       # String-based data.
#       #
#       # @param [byte[]] data The data to be searched.
#       # @param [byte[]] pattern The pattern to be searched for.
#       # @param [boolean] caseSensitive Flags whether or not the search is
#       #   case-sensitive.
#       # @param [int] from The offset within +data+ where the search should
#       #   begin.
#       # @param [int] to The offset within +data+ where the search should end.
#       #
#       # @return [int] The offset of the first occurrence of the pattern
#       #   within the specified bounds, or -1 if no match is found.
#       #
#       def indexOf(data, pattern, caseSensitive, from, to); end
#       alias index_of indexOf
#
#       # This method builds an HTTP message containing the specified headers
#       # and message body. If applicable, the Content-Length header will be
#       # added or updated, based on the length of the body.
#       #
#       # @param [List<String>] headers A list of headers to include in the
#       #   message.
#       # @param [byte[]] body The body of the message, of +nil+ if the message
#       #   has an empty body.
#       #
#       # @return [byte[]] The resulting full HTTP message.
#       #
#       def buildHttpMessage(headers, body); end
#       alias build_http_message buildHttpMessage
#
#       # This method creates a GET request to the specified URL. The headers
#       # used in the request are determined by the Request headers settings as
#       # configured in Burp Spider's options.
#       #
#       # @param [URL] url The URL to which the request should be made.
#       #
#       # @return [byte[]] A request to the specified URL.
#       #
#       def buildHttpRequest(url); end
#       alias build_http_request buildHttpRequest
#
#       # This method adds a new parameter to an HTTP request, and if
#       # appropriate updates the Content-Length header.
#       #
#       # @param [byte[]] request The request to which the parameter should be
#       #   added.
#       # @param [IParameter] parameter An {IParameter} object containing
#       #   details of the parameter to be added. Supported parameter types
#       #   are: +PARAM_URL+, +PARAM_BODY+ and +PARAM_COOKIE+.
#       #
#       # @return [byte[]] A new HTTP request with the new parameter added.
#       #
#       def addParameter(request, parameter); end
#       alias add_parameter addParameter
#
#       # This method removes a parameter from an HTTP request, and if
#       # appropriate updates the Content-Length header.
#       #
#       # @param [byte[]] request The request from which the parameter should
#       #   be removed.
#       # @param [IParameter] parameter An {IParameter} object containing
#       #   details of the parameter to be removed. Supported parameter types
#       #   are: +PARAM_URL+, +PARAM_BODY+ and +PARAM_COOKIE+.
#       #
#       # @return [byte[]] A new HTTP request with the parameter removed.
#       #
#       def removeParameter(request, parameter); end
#       alias remove_parameter removeParameter
#
#       # This method updates the value of a parameter within an HTTP request,
#       # and if appropriate updates the Content-Length header.
#       #
#       # @note This method can only be used to update the value of an existing
#       #   parameter of a specified type. If you need to change the type of an
#       #   existing parameter, you should first call {removeParameter} to
#       #   remove the parameter with the old type, and then call
#       #   {addParameter} to add a parameter with the new type.
#       # @param [byte[]] request The request containing the parameter to be
#       #   updated.
#       # @param [IParameter] parameter An {IParameter} object containing
#       #   details of the parameter to be updated. Supported parameter types
#       #   are: +PARAM_URL+, +PARAM_BODY+ and +PARAM_COOKIE+.
#       #
#       # @return [byte[]] A new HTTP request with the parameter updated.
#       #
#       def updateParameter(request, parameter); end
#       alias update_parameter updateParameter
#
#       # This method can be used to toggle a request's method between GET and
#       # POST. Parameters are relocated between the URL query string and
#       # message body as required, and the Content-Length header is created or
#       # removed as applicable.
#       #
#       # @param [byte[]] request The HTTP request whose method should be
#       #   toggled.
#       #
#       # @return [byte[]] A new HTTP request using the toggled method.
#       #
#       def toggleRequestMethod(request); end
#       alias toggle_request_method toggleRequestMethod
#
#       # This method constructs an {IHttpService} object based on the details
#       # provided.
#       #
#       # @param [String] host The HTTP service host.
#       # @param [int] port The HTTP service port.
#       # @param [String] protocol The HTTP service protocol.
#       #
#       # @return [IHttpService] An {IHttpService} object based on the details
#       #   provided.
#       #
#       def buildHttpService(host, port, protocol); end
#       alias build_http_service buildHttpService
#
#       # This method constructs an {IHttpService} object based on the details
#       # provided.
#       #
#       # @param [String] host The HTTP service host.
#       # @param [int] port The HTTP service port.
#       # @param [boolean] useHttps Flags whether the HTTP service protocol is
#       #   HTTPS or HTTP.
#       #
#       # @return [IHttpService] An {IHttpService} object based on the details
#       #   provided.
#       #
#       def buildHttpService(host, port, useHttps); end
#       alias build_http_service buildHttpService
#
#       # This method constructs an {IParameter} object based on the details
#       # provided.
#       #
#       # @param [String] name The parameter name.
#       # @param [String] value The parameter value.
#       # @param [byte] type The parameter type, as defined in the {IParameter}
#       #   interface.
#       #
#       # @return [IParameter] An {IParameter} object based on the details
#       #   provided.
#       #
#       def buildParameter(name, value, type); end
#       alias build_parameter buildParameter
#
#       # This method constructs an {IScannerInsertionPoint} object based on
#       # the details provided. It can be used to quickly create a simple
#       # insertion point based on a fixed payload location within a base
#       # request.
#       #
#       # @param [String] insertionPointName The name of the insertion point.
#       # @param [byte[]] baseRequest The request from which to build scan
#       #   requests.
#       # @param [int] from The offset of the start of the payload location.
#       # @param [int] to The offset of the end of the payload location.
#       #
#       # @return [IScannerInsertionPoint] An {IScannerInsertionPoint} object
#       #   based on the details provided.
#       #
#       def makeScannerInsertionPoint(insertionPointName, baseRequest, from, to); end
#       alias make_scanner_insertion_point makeScannerInsertionPoint
#     end
#   end

# @!parse
#   module Burp
#     # This interface is used to retrieve and update details about HTTP
#     # messages.
#     #
#     # @note The setter methods generally can only be used before the message
#     #   has been processed, and not in read-only contexts. The getter methods
#     #   relating to response details can only be used after the request has
#     #   been issued.
#     #
#     module IHttpRequestResponse
#       # This method is used to retrieve the request message.
#       #
#       # @return [byte[]] The request message.
#       #
#       def getRequest; end
#       alias get_request getRequest
#       alias request getRequest
#
#       # This method is used to update the request message.
#       #
#       # @param [byte[]] message The new request message.
#       #
#       # @return [void]
#       #
#       def setRequest(message); end
#       alias set_request setRequest
#       alias request= setRequest
#
#       # This method is used to retrieve the response message.
#       #
#       # @return [byte[]] The response message.
#       #
#       def getResponse; end
#       alias get_response getResponse
#       alias response getResponse
#
#       # This method is used to update the response message.
#       #
#       # @param [byte[]] message The new response message.
#       #
#       # @return [void]
#       #
#       def setResponse(message); end
#       alias set_response setResponse
#       alias response= setResponse
#
#       # This method is used to retrieve the user-annotated comment for this
#       # item, if applicable.
#       #
#       # @return [String, nil] The user-annotated comment for this item, or
#       #   +nil+ if none is set.
#       #
#       def getComment; end
#       alias get_comment getComment
#       alias comment getComment
#
#       # This method is used to update the user-annotated comment for this
#       # item.
#       #
#       # @param [String] comment The comment to be assigned to this item.
#       #
#       # @return [void]
#       #
#       def setComment(comment); end
#       alias set_comment setComment
#       alias comment= setComment
#
#       # This method is used to retrieve the user-annotated highlight for this
#       # item, if applicable.
#       #
#       # @return [String, nil] The user-annotated highlight for this item, or
#       #   +nil+ if none is set.
#       #
#       def getHighlight; end
#       alias get_highlight getHighlight
#       alias highlight getHighlight
#
#       # This method is used to update the user-annotated highlight for this
#       # item.
#       #
#       # @param [String, nil] color The highlight color to be assigned to this
#       #   item. Accepted values are: red, orange, yellow, green, cyan, blue,
#       #   pink, magenta, gray, or +nil+ to clear any existing highlight.
#       #
#       # @return [void]
#       #
#       def setHighlight(color); end
#       alias set_highlight setHighlight
#       alias highlight= setHighlight
#
#       # This method is used to retrieve the HTTP service for this request /
#       # response.
#       #
#       # @return [IHttpService] An {IHttpService} object containing details of
#       #   the HTTP service.
#       #
#       def getHttpService; end
#       alias get_http_service getHttpService
#       alias http_service getHttpService
#
#       # This method is used to update the HTTP service for this request /
#       # response.
#       #
#       # @param [IHttpService] httpService An {IHttpService} object containing
#       #   details of the new HTTP service.
#       #
#       # @return [void]
#       #
#       def setHttpService(httpService); end
#       alias set_http_service setHttpService
#       alias http_service= setHttpService
#     end
#   end

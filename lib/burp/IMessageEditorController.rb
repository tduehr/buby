# @!parse
#   module Burp
#     # This interface is used by an {IMessageEditor} to obtain details about
#     # the currently displayed message.
#     #
#     # Extensions that create instances of Burp's HTTP message editor can
#     # optionally provide an implementation of {IMessageEditorController},
#     # which the editor will invoke when it requires further information about
#     # the current message (for example, to send it to another Burp tool).
#     #
#     # Extensions that provide custom editor tabs via an
#     # {IMessageEditorTabFactory} will receive a reference to an
#     # {IMessageEditorController} object for each tab instance they generate,
#     # which the tab can invoke if it requires further information about the
#     # current message.
#     #
#     module IMessageEditorController
#       # This method is used to retrieve the HTTP service for the current
#       # message.
#       #
#       # @return [IHttpService] The HTTP service for the current message.
#       #
#       def getHttpService; end
#       alias get_http_service getHttpService
#       alias http_service getHttpService
#
#       # This method is used to retrieve the HTTP request associated with the
#       # current message (which may itself be a response).
#       #
#       # @return [byte[]] The HTTP request associated with the current
#       #   message.
#       #
#       def getRequest; end
#       alias get_request getRequest
#       alias request getRequest
#
#       # This method is used to retrieve the HTTP response associated with the
#       # current message (which may itself be a request).
#       #
#       # @return [byte[]] The HTTP response associated with the current
#       #   message.
#       #
#       def getResponse; end
#       alias get_response getResponse
#       alias response getResponse
#     end
#   end

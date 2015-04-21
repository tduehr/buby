# @!parse
#   module Burp
#     # This interface is used for an {IHttpRequestResponse} object whose
#     # request and response messages have been saved to temporary files using
#     # {IBurpExtenderCallbacks#saveBuffersToTempFiles}.
#     module IHttpRequestResponsePersisted
#       include IHttpRequestResponse
#
#       # This method is deprecated and no longer performs any action.
#       #
#       # @return [void]
#       #
#       # @deprecated
#       #
#       def deleteTempFiles; end
#       alias delete_temp_files deleteTempFiles
#     end
#   end

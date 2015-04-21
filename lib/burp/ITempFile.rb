# @!parse
#   module Burp
#     # This interface is used to hold details of a temporary file that has
#     # been created via a call to {IBurpExtenderCallbacks#saveToTempFile}.
#     #
#     #
#     module ITempFile
#       # This method is used to retrieve the contents of the buffer that was
#       # saved in the temporary file.
#       #
#       # @return [byte[]] The contents of the buffer that was saved in the
#       #   temporary file.
#       #
#       def getBuffer; end
#       alias get_buffer getBuffer
#       alias buffer getBuffer
#
#       # This method is deprecated and no longer performs any action.
#       #
#       # @deprecated
#       #
#       # @return [void]
#       #
#       def delete; end
#     end
#   end

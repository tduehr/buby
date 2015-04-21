# @!parse
#   module Burp
#     # This interface is used to provide extensions with an instance of Burp's
#     # HTTP message editor, for the extension to use in its own UI. Extensions
#     # should call {IBurpExtenderCallbacks#createMessageEditor} to obtain an
#     # instance of this interface.
#     #
#     module IMessageEditor
#       # This method returns the UI component of the editor, for extensions to
#       # add to their own UI.
#       #
#       # @return [Component] The UI component of the editor.
#       #
#       def getComponent; end
#       alias get_component getComponent
#       alias component getComponent
#
#       # This method is used to display an HTTP message in the editor.
#       #
#       # @param [byte[]] message The HTTP message to be displayed.
#       # @param [boolean] isRequest Flags whether the message is an HTTP
#       #   request or response.
#       #
#       # @return [void]
#       #
#       def setMessage(message, isRequest); end
#       alias set_message setMessage
#       alias message= setMessage
#
#       # This method is used to retrieve the currently displayed message,
#       # which may have been modified by the user.
#       #
#       # @return [byte[]] The currently displayed HTTP message.
#       #
#       def getMessage; end
#       alias get_message getMessage
#       alias message getMessage
#
#       # This method is used to determine whether the current message has been
#       # modified by the user.
#       #
#       # @return [boolean] An indication of whether the current message has
#       #   been modified by the user since it was first displayed.
#       #
#       def isMessageModified; end
#       alias is_message_modified isMessageModified
#       alias message_modified? isMessageModified
#
#       # This method returns the data that is currently selected by the user.
#       #
#       # @return [byte[]] The data that is currently selected by the user, or
#       #   +nil+ if no selection is made.
#       #
#       def getSelectedData; end
#       alias get_selected_data getSelectedData
#       alias selected_data getSelectedData
#     end
#   end

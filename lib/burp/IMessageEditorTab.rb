# @!parse
#   module Burp
#     # Extensions that register an {IMessageEditorTabFactory} must return
#     # instances of this interface, which Burp will use to create custom tabs
#     # within its HTTP message editors.
#     #
#     module IMessageEditorTab
#       # This method returns the caption that should appear on the custom tab
#       # when it is displayed.
#       #
#       # @note Burp invokes this method once when the tab is first generated,
#       #   and the same caption will be used every time the tab is displayed.
#       #
#       # @return [String] The caption that should appear on the custom tab
#       #   when it is displayed.
#       #
#       def getTabCaption; end
#       alias get_tab_caption getTabCaption
#       alias tab_caption getTabCaption
#
#       # This method returns the component that should be used as the contents
#       # of the custom tab when it is displayed.
#       #
#       # @note Burp invokes this method once when the tab is first generated,
#       #   and the same component will be used every time the tab is
#       #   displayed.
#       #
#       # @return [Component] The component that should be used as the contents
#       #   of the custom tab when it is displayed.
#       #
#       def getUiComponent; end
#       alias get_ui_component getUiComponent
#       alias ui_component getUiComponent
#
#       # The hosting editor will invoke this method before it displays a new
#       # HTTP message, so that the custom tab can indicate whether it should
#       # be enabled for that message.
#       #
#       # @param [byte[]] content The message that is about to be displayed.
#       # @param [boolean] isRequest Indicates whether the message is a request
#       #   or a response.
#       #
#       # @return [boolean] The method should return +true+ if the custom tab
#       #   is able to handle the specified message, and so will be displayed
#       #   within the editor. Otherwise, the tab will be hidden while this
#       #   message is displayed.
#       #
#       def isEnabled(content, isRequest); end
#       alias is_enabled isEnabled
#       alias enabled? isEnabled
#
#       # The hosting editor will invoke this method to display a new message
#       # or to clear the existing message. This method will only be called
#       # with a new message if the tab has already returned +true+ to a call
#       # to {isEnabled} with the same message details.
#       #
#       # @param [byte[]] content The message that is to be displayed, or +nil+
#       #   if the tab should clear its contents and disable any editable
#       #   controls.
#       # @param [boolean] isRequest Indicates whether the message is a request
#       #   or a response.
#       #
#       # @return [void]
#       #
#       def setMessage(content, isRequest); end
#       alias set_message setMessage
#       alias message= setMessage
#
#       # This method returns the currently displayed message.
#       #
#       # @return [byte[]] The currently displayed message.
#       #
#       def getMessage; end
#       alias get_message getMessage
#       alias message getMessage
#
#       # This method is used to determine whether the currently displayed
#       # message has been modified by the user. The hosting editor will always
#       # call {getMessage} before calling this method, so any pending edits
#       # should be completed within {getMessage}.
#       #
#       # @return [boolean] The method should return +true+ if the user has
#       #   modified the current message since it was first displayed.
#       #
#       def isModified; end
#       alias is_modified isModified
#       alias modified? isModified
#
#       # This method is used to retrieve the data that is currently selected
#       # by the user.
#       #
#       # @return [byte[]] The data that is currently selected by the user.
#       #   This may be +nil+ if no selection is currently made.
#       #
#       def getSelectedData; end
#       alias get_selected_data getSelectedData
#       alias selected_data getSelectedData
#     end
#   end

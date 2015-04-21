# @!parse
#   module Burp
#     # This interface is used when Burp calls into an extension-provided
#     # {IContextMenuFactory} with details of a context menu invocation. The
#     # custom context menu factory can query this interface to obtain details
#     # of the invocation event, in order to determine what menu items should
#     # be displayed.
#     #
#     module IContextMenuInvocation
#       # Used to indicate that the context menu is being invoked in a request
#       # editor.
#       #
#       # # CONTEXT_MESSAGE_EDITOR_REQUEST = 0;
#
#       # Used to indicate that the context menu is being invoked in a response
#       # editor.
#       #
#       # # CONTEXT_MESSAGE_EDITOR_RESPONSE = 1;
#
#       # Used to indicate that the context menu is being invoked in a
#       # non-editable request viewer.
#       #
#       # # CONTEXT_MESSAGE_VIEWER_REQUEST = 2;
#
#       # Used to indicate that the context menu is being invoked in a
#       # non-editable response viewer.
#       #
#       # # CONTEXT_MESSAGE_VIEWER_RESPONSE = 3;
#
#       # Used to indicate that the context menu is being invoked in the Target
#       # site map tree.
#       #
#       # # CONTEXT_TARGET_SITE_MAP_TREE = 4;
#
#       # Used to indicate that the context menu is being invoked in the Target
#       # site map table.
#       #
#       # # CONTEXT_TARGET_SITE_MAP_TABLE = 5;
#
#       # Used to indicate that the context menu is being invoked in the Proxy
#       # history.
#       #
#       # # CONTEXT_PROXY_HISTORY = 6;
#
#       # Used to indicate that the context menu is being invoked in the
#       # Scanner results.
#       #
#       # # CONTEXT_SCANNER_RESULTS = 7;
#
#       # Used to indicate that the context menu is being invoked in the
#       # Intruder payload positions editor.
#       #
#       # # CONTEXT_INTRUDER_PAYLOAD_POSITIONS = 8;
#
#       # Used to indicate that the context menu is being invoked in an
#       # Intruder attack results.
#       #
#       # # CONTEXT_INTRUDER_ATTACK_RESULTS = 9;
#
#       # Used to indicate that the context menu is being invoked in a search
#       # results window.
#       #
#       # # CONTEXT_SEARCH_RESULTS = 10;
#
#       # This method can be used to retrieve the native Java input event that
#       # was the trigger for the context menu invocation.
#       #
#       # @return [InputEvent] The {InputEvent} that was the trigger for the
#       #   context menu invocation.
#       #
#       def getInputEvent; end
#       alias get_input_event getInputEvent
#       alias input_event getInputEvent
#
#       # This method can be used to retrieve the Burp tool within which the
#       # context menu was invoked.
#       #
#       # @return [int] A flag indicating the Burp tool within which the
#       #   context menu was invoked. Burp tool flags are defined in the
#       #   {IBurpExtenderCallbacks} interface.
#       #
#       def getToolFlag; end
#       alias get_tool_flag getToolFlag
#       alias tool_flag getToolFlag
#
#       # This method can be used to retrieve the context within which the menu
#       # was invoked.
#       #
#       # @return [byte] An index indicating the context within which the menu
#       #   was invoked. The indices used are defined within this interface.
#       #
#       def getInvocationContext; end
#       alias get_invocation_context getInvocationContext
#       alias invocation_context getInvocationContext
#
#       # This method can be used to retrieve the bounds of the user's
#       # selection into the current message, if applicable.
#       #
#       # @return [Array<int>] An +int[2]+ array containing the start and end
#       #   offsets of the user's selection in the current message. If the user
#       #   has not made any selection in the current message, both offsets
#       #   indicate the position of the caret within the editor. If the menu
#       #   is not being invoked from a message editor, the method returns
#       #   +nil+.
#       #
#       def getSelectionBounds; end
#       alias get_selection_bounds getSelectionBounds
#       alias selection_bounds getSelectionBounds
#
#       # This method can be used to retrieve details of the HTTP requests /
#       # responses that were shown or selected by the user when the context
#       # menu was invoked.
#       #
#       # @note For performance reasons, the objects returned from this method
#       #   are tied to the originating context of the messages within the Burp
#       #   UI. For example, if a context menu is invoked on the Proxy
#       #   intercept panel, then the {IHttpRequestResponse} returned by this
#       #   method will reflect the current contents of the interception panel,
#       #   and this will change when the current message has been forwarded or
#       #   dropped. If your extension needs to store details of the message
#       #   for which the context menu has been invoked, then you should query
#       #   those details from the {IHttpRequestResponse} at the time of
#       #   invocation, or you should use
#       #   {IBurpExtenderCallbacks#saveBuffersToTempFiles} to create a
#       #   persistent read-only copy of the {IHttpRequestResponse}.
#       #
#       # @return [Array<IHttpRequestResponse>] An array of
#       #   {IHttpRequestResponse} objects representing the items that were
#       #   shown or selected by the user when the context menu was invoked.
#       #   This method returns +nil+ if no messages are applicable to the
#       #   invocation.
#       #
#       def getSelectedMessages; end
#       alias get_selected_messages getSelectedMessages
#       alias selected_messages getSelectedMessages
#
#       # This method can be used to retrieve details of the Scanner issues
#       # that were selected by the user when the context menu was invoked.
#       #
#       # @return [Array<IScanIssue>] An array of {IScanIssue} objects
#       #   representing the issues that were selected by the user when the
#       #   context menu was invoked. This method returns +nil+ if no Scanner
#       #   issues are applicable to the invocation.
#       #
#       def getSelectedIssues; end
#       alias get_selected_issues getSelectedIssues
#       alias selected_issues getSelectedIssues
#     end
#   end

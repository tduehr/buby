# @!parse
#   module Burp
#     # This interface is used to provide extensions with an instance of Burp's
#     # raw text editor, for the extension to use in its own UI. Extensions
#     # should call {IBurpExtenderCallbacks#createTextEditor} to obtain an
#     # instance of this interface.
#     #
#     module ITextEditor
#       # This method returns the UI component of the editor, for extensions to
#       # add to their own UI.
#       #
#       # @return [Component] The UI component of the editor.
#       #
#       def getComponent; end
#       alias get_component getComponent
#       alias component getComponent
#
#       # This method is used to control whether the editor is currently
#       # editable. This status can be toggled on and off as required.
#       #
#       # @param [boolean] editable Indicates whether the editor should be
#       #   currently editable.
#       #
#       # @return [void]
#       #
#       def setEditable(editable); end
#       alias set_editable setEditable
#       alias editable= setEditable
#
#       # This method is used to update the currently displayed text in the
#       # editor.
#       #
#       # @param [byte[]] text The text to be displayed.
#       #
#       # @return [void]
#       #
#       def setText(text); end
#       alias set_text setText
#       alias text= setText
#
#       # This method is used to retrieve the currently displayed text.
#       #
#       # @return [byte[]] The currently displayed text.
#       #
#       def getText; end
#       alias get_text getText
#       alias text getText
#
#       # This method is used to determine whether the user has modified the
#       # contents of the editor.
#       #
#       # @return [boolean] An indication of whether the user has modified the
#       #   contents of the editor since the last call to {setText}.
#       #
#       def isTextModified; end
#       alias is_text_modified isTextModified
#       alias text_modified? isTextModified
#
#       # This method is used to obtain the currently selected text.
#       #
#       # @return [byte[]] The currently selected text, or +nil+ if the user
#       #   has not made any selection.
#       #
#       def getSelectedText; end
#       alias get_selected_text getSelectedText
#       alias selected_text getSelectedText
#
#       # This method can be used to retrieve the bounds of the user's
#       # selection into the displayed text, if applicable.
#       #
#       # @return [Array<Array<int>>] An +int[2]+ array containing the start
#       #   and end offsets of the user's selection within the displayed text.
#       #   If the user has not made any selection in the current message, both
#       #   offsets indicate the position of the caret within the editor.
#       #
#       def getSelectionBounds; end
#       alias get_selection_bounds getSelectionBounds
#       alias selection_bounds getSelectionBounds
#
#       # This method is used to update the search expression that is shown in
#       # the search bar below the editor. The editor will automatically
#       # highlight any regions of the displayed text that match the search
#       # expression.
#       #
#       # @param [String] expression The search expression.
#       #
#       # @return [void]
#       #
#       def setSearchExpression(expression); end
#       alias set_search_expression setSearchExpression
#       alias search_expression= setSearchExpression
#     end
#   end

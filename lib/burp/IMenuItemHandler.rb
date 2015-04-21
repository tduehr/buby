# @!parse
#   module Burp
#     # Extensions can implement this interface and then call
#     # {IBurpExtenderCallbacks#registerMenuItem} to register a custom context
#     # menu item.
#     #
#     # @deprecated Use {IContextMenuFactory} instead.
#     #
#     module IMenuItemHandler
#       # This method is invoked by Burp Suite when the user clicks on a custom
#       # menu item which the extension has registered with Burp.
#       #
#       # @param [String] menuItemCaption The caption of the menu item which
#       #   was clicked. This parameter enables extensions to provide a single
#       #   implementation which handles multiple different menu items.
#       # @param [Array<IHttpRequestResponse>] messageInfo Details of the HTTP
#       #   message(s) for which the context menu was displayed.
#       #
#       # @return [void]
#       #
#       def menuItemClicked(menuItemCaption, messageInfo); end
#       alias menu_item_clicked menuItemClicked
#     end
#   end

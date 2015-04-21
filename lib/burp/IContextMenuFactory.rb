# @!parse
#   module Burp
#     # Extensions can implement this interface and then call
#     # {IBurpExtenderCallbacks#registerContextMenuFactory} to register a
#     # factory for custom context menu items.
#     #
#     module IContextMenuFactory
#       # This method will be called by Burp when the user invokes a context
#       # menu anywhere within Burp. The factory can then provide any custom
#       # context menu items that should be displayed in the context menu,
#       # based on the details of the menu invocation.
#       #
#       # @param [IContextMenuInvocation] invocation An object that implements
#       #   the {IMessageEditorTabFactory} interface, which the extension can
#       #   query to obtain details of the context menu invocation.
#       #
#       # @return [Array<JMenuItem>, nil] A list of custom menu items (which
#       #   may include sub-menus, checkbox menu items, etc.) that should be
#       #   displayed. Extensions may return +nil+ from this method, to
#       #   indicate that no menu items are required.
#       #
#       def createMenuItems(invocation); end
#       alias create_menu_items createMenuItems
#     end
#   end

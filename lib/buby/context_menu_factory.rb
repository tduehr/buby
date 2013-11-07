class Buby
  # Extensions can implement this interface and then call
  # <code>IBurpExtenderCallbacks.registerContextMenuFactory()</code> to register
  # a factory for custom context menu items.
  #
  class ContextMenuFactory
    include Java::Burp::IContextMenuFactory

    # This method will be called by Burp when the user invokes a context menu
    # anywhere within Burp. The factory can then provide any custom context
    # menu items that should be displayed in the context menu, based on the
    # details of the menu invocation.
    # Implementations should call super
    #
    # @param [IContextMenuInvocation] invocation An object the extension can
    #   query to obtain details of the context menu invocation.
    # @return [Array<JMenuItem>] A list of custom menu items (which may include
    #   sub-menus, checkbox menu items, etc.) that should be displayed.
    #   Extensions may return +nil+ from this method, to indicate that no menu
    #   items are required.
    # @deprecated
    #
    def self.createMenuItems invocation
      pp [:got_create_menu_items, invocation] if $DEBUG
      Buby::Implants::ContextMenuInvocation.implant invocation
      nil
    end

    # This method will be called by Burp when the user invokes a context menu
    # anywhere within Burp. The factory can then provide any custom context
    # menu items that should be displayed in the context menu, based on the
    # details of the menu invocation.
    # This method calls create_menu_items after implanting the invocation class.
    # Redefine to bypass this behavior
    #
    # @param [IContextMenuInvocation] invocation An object the extension can
    #   query to obtain details of the context menu invocation.
    # @return [Array<JMenuItem>] A list of custom menu items (which may include
    #   sub-menus, checkbox menu items, etc.) that should be displayed.
    #   Extensions may return +nil+ from this method, to indicate that no menu
    #   items are required.
    #
    def createMenuItems invocation
      pp [:got_create_menu_items, invocation] if $DEBUG
      create_menu_items Buby::Implants::ContextMenuInvocation.implant(invocation)
    end

    # This method will be called by Burp when the user invokes a context menu
    # anywhere within Burp. The factory can then provide any custom context
    # menu items that should be displayed in the context menu, based on the
    # details of the menu invocation.
    #
    # @param [IContextMenuInvocation] invocation An object the extension can
    #   query to obtain details of the context menu invocation.
    # @return [Array<JMenuItem>] A list of custom menu items (which may include
    #   sub-menus, checkbox menu items, etc.) that should be displayed.
    #   Extensions may return +nil+ from this method, to indicate that no menu
    #   items are required.
    #
    def create_menu_items invocation
      nil
    end
  end
end

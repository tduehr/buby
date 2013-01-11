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
    # @param invocation An object that implements the
    # <code>IMessageEditorTabFactory</code> interface, which the extension can
    # query to obtain details of the context menu invocation.
    # @return A list of custom menu items (which may include sub-menus,
    # checkbox menu items, etc.) that should be displayed. Extensions may
    # return
    # <code>null</code> from this method, to indicate that no menu items are
    # required.
    #
    def self.createMenuItems invocation
      pp [:got_create_menu_items, invocation] if $DEBUG
      ContextMenuInvocation.implant invocation
      nil
    end

    def createMenuItems invocation
      pp [:got_create_menu_items, invocation] if $DEBUG
      ContextMenuInvocation.implant invocation
      nil
    end
  end

  module Implants
    # This interface is used when Burp calls into an extension-provided
    # <code>IContextMenuFactory</code> with details of a context menu
    # invocation. The custom context menu factory can query this interface to
    # obtain details of the invocation event, in order to determine what menu
    # items should be displayed.
    # This module is used to extend the JRuby proxy class returned by Burp.
    #
    module ContextMenuInvocation
      include Buby::Implants::Proxy

      # Context menu is being invoked in a request editor.
      CONTEXT_MESSAGE_EDITOR_REQUEST = 0;

      # Context menu is being invoked in a response editor.
      CONTEXT_MESSAGE_EDITOR_RESPONSE = 1;

      # Context menu is being invoked in a non-editable request viewer.
      CONTEXT_MESSAGE_VIEWER_REQUEST = 2;

      # Context menu is being invoked in a non-editable response viewer.
      CONTEXT_MESSAGE_VIEWER_RESPONSE = 3;

      # Context menu is being invoked in the Target site map tree.
      CONTEXT_TARGET_SITE_MAP_TREE = 4;

      # Context menu is being invoked in the Target site map table.
      CONTEXT_TARGET_SITE_MAP_TABLE = 5;

      # Context menu is being invoked in the Proxy history.
      CONTEXT_PROXY_HISTORY = 6;

      # Context menu is being invoked in the Scanner results.
      CONTEXT_SCANNER_RESULTS = 7;

      # Context menu is being invoked in the Intruder payload positions editor.
      CONTEXT_INTRUDER_PAYLOAD_POSITIONS = 8;

      # Context menu is being invoked in an Intruder attack results.
      CONTEXT_INTRUDER_ATTACK_RESULTS = 9;

      # Context menu is being invoked in a search results window.
      CONTEXT_SEARCH_RESULTS = 10;

      def getSelectedMessages
        pp [:got_get_selected_messages] if $DEBUG
        hrrl = __getSelectedMessages
        HttpRequestResponseHelper.implant(hrrl.first)
        hrrl
      end
    
      def getSelectedIssues
        pp [:got_get_selected_issues] if $DEBUG
        sil = __getSelectedIssues
        ScanIssueHelper.implant(sil.first)
        sil
      end

      # Install ourselves into the current IContextMenuInvocation java class
      # @param invocation IContextMenuInvocation
      #
      # @todo __persistent__?
      def self.implant(invocation)
        unless invocation.implanted? || invocation.nil?
          pp [:implanting, invocation, invocation.class] if $DEBUG
          invocation.class.class_eval do
             alias_method :__getSelectedMessages, :getSelectedMessages
             alias_method :__getSelectedIssues, :getSelectedIssues
             include Burp::Implants::ContextMenuInvocation
             rewrap_java_method :getSelectedMessages
             rewrap_java_method :getSelectedIssues
          end
        end
        invocation
      end
    end
  end
end

class Buby
  module Implants
    # This interface is used when Burp calls into an extension-provided
    # <code>IContextMenuFactory</code> with details of a context menu
    # invocation. The custom context menu factory can query this interface to
    # obtain details of the invocation event, in order to determine what menu
    # items should be displayed.
    # This module is used to extend the JRuby proxy class returned by Burp.
    #
    module ContextMenuInvocation
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

      # Install ourselves into the current +IContextMenuInvocation+ java class
      # @param [IContextMenuInvocation] context_menu_invocation
      #
      # @todo __persistent__?
      def self.implant(context_menu_invocation)
        unless context_menu_invocation.implanted? || context_menu_invocation.nil?
          pp [:implanting, context_menu_invocation, context_menu_invocation.class] if 
          context_menu_invocation.class.class_exec(context_menu_invocation) do |context_menu_invocation|
            a_methods = %w{
              getSelectedMessages
              getSelectedIssues
            }
            a_methods.each do |meth|
              alias_method "__"+meth.to_s, meth
            end
            include Buby::Implants::ContextMenuInvocation
            a_methods.each do |meth|
              java_class.ruby_names_for_java_method(meth).each do |ruby_meth|
                define_method ruby_meth, Buby::Implants::curr_mod.instance_method(meth)
              end
            end
            include Buby::Implants::Proxy
          end
        end
        context_menu_invocation
      end
    end
  end
end

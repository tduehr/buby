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

      # This method can be used to retrieve details of the HTTP requests /
      # responses that were shown or selected by the user when the context menu
      # was invoked.
      #
      # @note For performance reasons, the objects returned from this method are
      #   tied to the originating context of the messages within the Burp UI.
      #   For example, if a context menu is invoked on the Proxy intercept
      #   panel, then the +IHttpRequestResponse+ returned by this method will
      #   reflect the current contents of the interception panel, and this will
      #   change when the current message has been forwarded or dropped. If your
      #   extension needs to store details of the message for which the context
      #   menu has been invoked, then you should query those details from the
      #   +IHttpRequestResponse+ at the time of invocation, or you should use
      #   +IBurpExtenderCallbacks.saveBuffersToTempFiles()+ to create a
      #   persistent read-only copy of the +IHttpRequestResponse+.
      #
      # @return [HttpRequestResponseList,nil] An array of objects
      #   representing the items that were shown or selected by the user when
      #   the context menu was invoked. This method returns +nil+ if no messages
      #   are applicable to the invocation.
      #
      def getSelectedMessages
        pp [:got_get_selected_messages] if $DEBUG
        HttpRequestResponseList.new(__getSelectedMessages)
      end

      # This method can be used to retrieve details of the Scanner issues that
      # were selected by the user when the context menu was invoked.
      #
      # @return [ScanIssuesList,nil] The issues that were selected by the
      #   user when the context menu was invoked. This method returns +nil+ if
      #   no Scanner issues are applicable to the invocation.
      #
      def getSelectedIssues
        pp [:got_get_selected_issues] if $DEBUG
        ScanIssuesList.new(__getSelectedIssues)
      end

      # Install ourselves into the current +IContextMenuInvocation+ java class
      # @param [IContextMenuInvocation] invocation
      #
      def self.implant(invocation)
        unless invocation.implanted? || invocation.nil?
          pp [:implanting, invocation, invocation.class] if $DEBUG
          invocation.class.class_exec(invocation) do |invocation|
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
                define_method ruby_meth, Buby::Implants::ContextMenuInvocation.instance_method(meth)
              end
            end
            include Buby::Implants::Proxy
          end
        end
        invocation
      end
    end
  end
end

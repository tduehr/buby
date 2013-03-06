class Buby
  # This is the JRuby implementation of IBurpExtender for use as a JRuby
  # extension. This class handles the type conversions and other ruby sugar.
  # {BurpExtender} further extends this by adding additional things during
  # startup, like setting up Buby as the handler class and starting console
  # tabs.
  # 
  # @note This class, unlike the Java implementation, does not fire the
  #   deprecated evt_* callbacks, only the new versions.
  #
  # @todo move implant logic to extender interfaces
  module Extender
    include Java::Burp::IBurpExtender
    include Java::Burp::IExtensionStateListener
    include Java::Burp::IProxyListener
    include Java::Burp::IHttpListener
    include Java::Burp::IScannerListener
    include Java::Burp::IScopeChangeListener
    include Java::Burp::IContextMenuFactory

    # @group Buby internals
    # Internal reference to ruby handler class (usually {Buby})
    @@handler = nil

    # Returns the internal Ruby handler reference. 
    #
    # The handler is the ruby class or module used for proxying BurpExtender 
    # events into a ruby runtime. Usually, this is Buby or a subclass.
    #
    def self.handler
      @@handler
    end

    # Sets an internal reference to the ruby handler class or module to use for
    # proxied BurpExtender events into a ruby runtime.
    #
    # Generally, this should probably be called in {#registerExtenderCallbacks}.
    # However, it is also possible to set this afterwards and even swap in new
    # objects during runtime.
    #
    def self.handler=(hndlr)
      @@handler = hndlr
    end

    def handler
      @@handler
    end

    def handler= hndlr
      @@handler = hndlr
    end

    # @group Burp extender
    # This callback usually fires before the handler is set.
    #
    def initialize *args
      @@handler.extender_initialize(*args) if @@handler.respond_to? :extender_inititialize
    end

    # This method is invoked when the extension is loaded. It registers an
    # instance of the +IBurpExtenderCallbacks+ interface, providing methods that
    # may be invoked by the extension to perform various actions.
    #
    # @param [IBurpExtenderCallbacks] callbacks Burp's Java object for querying
    #   Burp's data.
    # @return [void]
    #
    def registerExtenderCallbacks(callbacks)
      @callbacks = callbacks
      callbacks.issueAlert("[#{self.class}] registering JRuby handler callbacks")
      callbacks.registerExtensionStateListener(self)
      callbacks.registerHttpListener(self)
      callbacks.registerScannerListener(self)
      callbacks.registerContextMenuFactory self
      callbacks.registerScopeChangeListener self
      @@handler.register_callbacks(callbacks) if @@handler.respond_to? :register_callbacks
    end

    # @group Listeners
    # This method is called when the extension is unloaded. This, in turn, calls
    # {Buby#extension_unloaded} on the handler instance
    #
    def extensionUnloaded
      @@handler.extension_unloaded if @@handler.respond_to? :extension_unloaded
    end

    # This method is invoked when an HTTP message is being processed by the
    # Proxy and calls {Buby#process_proxy_message} on the handler.
    #
    # @param [Boolean] messageIsRequest Indicates whether the HTTP message is a
    #   request or a response.
    # @param [IInterceptedProxyMessage] message An +IInterceptedProxyMessage+
    #   object that extensions can use to query and update details of the
    #   message, and control whether the message should be intercepted and
    #   displayed to the user for manual review or modification.
    # @return [void]
    #
    def processProxyMessage(messageIsRequest, message)
      @@handler.process_proxy_message(messageIsRequest, message) if @@handler.respond_to? :process_proxy_message
    end

    # This method is invoked when an HTTP request is about to be issued, and
    # when an HTTP response has been received.
    #
    # @param [Fixnum] toolFlag A flag indicating the Burp tool that issued the
    #   request. Burp tool flags are defined in the +IBurpExtenderCallbacks+
    #   interface.
    # @param [Boolean] messageIsRequest Flags whether the method is being
    #   invoked for a request or response.
    # @param [IHttpRequestResponse] messageInfo Details of the request /
    #   response to be processed. Extensions can call the setter methods on this
    #   object to update the current message and so modify Burp's behavior.
    # @return [void]
    #
    def processHttpMessage(toolFlag, messageIsRequest, messageInfo)
      @@handler.process_http_message(toolFlag, messageIsRequest, messageInfo) if @@handler.respond_to? :process_http_message
    end

    # This method is invoked when a new issue is added to Burp Scanner's
    # results.
    #
    # @param [IScanIssue] issue An +IScanIssue+ object that the extension can
    #   query to obtain details about the new issue.
    #
    def newScanIssue(issue)
      @@handler.new_scan_issue(issue) if @@handler.respond_to? :new_scan_issue
    end

    # This method will be called by Burp when the user invokes a context menu
    # anywhere within Burp. The factory can then provide any custom context menu
    # items that should be displayed in the context menu, based on the details
    # of the menu invocation.
    #
    # @param [IContextMenuInvocation] invocation An object the extension can
    #   query to obtain details of the context menu invocation.
    # @return [Array<JMenuItem>, nil] A list of custom menu items (which may
    #   include sub-menus, checkbox menu items, etc.) that should be displayed.
    #   Extensions may return +nil+ from this method, to indicate that no menu
    #   items are required.
    #
    # @abstract
    def createMenuItems invocation
      @@handler.create_menu_items(invocation) if @@handler.respond_to? :create_menu_items
    end

    # This method is invoked whenever a change occurs to Burp's suite-wide
    # target scope.
    #
    # @return [void]
    #
    # @abstract
    def scopeChanged
      @@handler.scope_changed if @@handler.respond_to? :scope_changed
    end
  end
end

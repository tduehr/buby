# @!parse
#   module Burp
#     # This interface is used by Burp Suite to pass to extensions a set of
#     # callback methods that can be used by extensions to perform various
#     # actions within Burp.
#     #
#     # When an extension is loaded, Burp invokes its
#     # {#registerExtenderCallbacks} method and passes an instance of the
#     # {IBurpExtenderCallbacks} interface. The extension may then invoke the
#     # methods of this interface as required in order to extend Burp's
#     # functionality.
#     #
#     module IBurpExtenderCallbacks
#       # Flag used to identify Burp Suite as a whole.
#       #
#       static final int TOOL_SUITE = 0x00000001;
#
#       # Flag used to identify the Burp Target tool.
#       #
#       static final int TOOL_TARGET = 0x00000002;
#
#       # Flag used to identify the Burp Proxy tool.
#       #
#       static final int TOOL_PROXY = 0x00000004;
#
#       # Flag used to identify the Burp Spider tool.
#       #
#       static final int TOOL_SPIDER = 0x00000008;
#
#       # Flag used to identify the Burp Scanner tool.
#       #
#       static final int TOOL_SCANNER = 0x00000010;
#
#       # Flag used to identify the Burp Intruder tool.
#       #
#       static final int TOOL_INTRUDER = 0x00000020;
#
#       # Flag used to identify the Burp Repeater tool.
#       #
#       static final int TOOL_REPEATER = 0x00000040;
#
#       # Flag used to identify the Burp Sequencer tool.
#       #
#       TOOL_SEQUENCER = 0x00000080;
#
#       # Flag used to identify the Burp Decoder tool.
#       #
#       static final int TOOL_DECODER = 0x00000100;
#
#       # Flag used to identify the Burp Comparer tool.
#       #
#       TOOL_COMPARER = 0x00000200;
#
#       # Flag used to identify the Burp Extender tool.
#       #
#       TOOL_EXTENDER = 0x00000400;
#
#       # This method is used to set the display name for the current
#       # extension, # which will be displayed within the user interface for
#       # the Extender tool.
#       #
#       # @param [String] name The extension name.
#       #
#       # @return [void]
#       def setExtensionName(name); end
#       alias set_extension_name setExtensionName
#       alias extension_name= setExtensionName
#
#       # This method is used to obtain an {IExtensionHelpers} object, which
#       # can be used by the extension to perform numerous useful tasks.
#       #
#       # @return [IExtensionHelpers] An object containing numerous helper
#       #   methods, for tasks such as building and analyzing HTTP requests.
#       #
#       def getHelpers; end
#       alias get_helpers getHelpers
#       alias helpers getHelpers
#
#       # This method is used to obtain the current extension's standard output
#       # stream. Extensions should write all output to this stream, allowing
#       # the Burp user to configure how that output is handled from within the
#       # UI.
#       #
#       # @return [OutputStream] The extension's standard output stream.
#       #
#       def getStdout; end
#       alias get_stdout getStdout
#       alias stdout getStdout
#
#       # This method is used to obtain the current extension's standard error
#       # stream. Extensions should write all error messages to this stream, *
#       # allowing the Burp user to configure how that output is handled from
#       # within the UI.
#       #
#       # @return [OutputStream] The extension's standard error stream.
#       #
#       def getStderr; end
#       alias get_stderr getStderr
#       alias stderr getStderr
#
#       # This method prints a line of output to the current extension's
#       # standard output stream.
#       #
#       # @param [String] output The message to print.
#       #
#       # @return [void]
#       def printOutput(output); end
#       alias print_output printOutput
#
#       # This method prints a line of output to the current extension's
#       # standard error stream.
#       #
#       # @param [String] error The message to print.
#       #
#       # @return [void]
#       def printError(error); end
#       alias print_error printError
#
#       # This method is used to register a listener which will be notified of
#       # changes to the extension's state. <b>Note:</b> Any extensions that
#       # start background threads or open system resources (such as files or
#       # database connections) should register a listener and terminate
#       # threads / close resources when the extension is unloaded.
#       #
#       # @param [IExtensionStateListener] listener An object created by the
#       #   extension that implements the {IExtensionStateListener} interface.
#       #
#       # @return [void]
#       def registerExtensionStateListener(listener); end
#       alias register_extension_state_listener registerExtensionStateListener
#
#       # This method is used to retrieve the extension state listeners that
#       # are registered by the extension.
#       #
#       # @return [Array<IExtensionStateListener>] A list of extension state
#       #   listeners that are currently registered by this extension.
#       #
#       def getExtensionStateListeners; end
#       alias get_extension_state_listeners getExtensionStateListeners
#       alias extension_state_listeners getExtensionStateListeners
#
#       # This method is used to remove an extension state listener that has
#       # been registered by the extension.
#       #
#       # @param [IExtensionStateListener] listener The extension state
#       #   listener to be removed.
#       #
#       # @return [void]
#       def removeExtensionStateListener(listener); end
#       alias remove_extension_state_listener removeExtensionStateListener
#
#       # This method is used to register a listener which will be notified of
#       # requests and responses made by any Burp tool. Extensions can perform
#       # custom analysis or modification of these messages by registering an
#       # HTTP listener.
#       #
#       # @param [IHttpListener] listener An object created by the extension
#       #   that implements the {IHttpListener} interface.
#       #
#       # @return [void]
#       def registerHttpListener(listener); end
#       alias register_http_listener registerHttpListener
#
#       # This method is used to retrieve the HTTP listeners that are
#       # registered by the extension.
#       #
#       # @return [Array<IHttpListener>] A list of HTTP listeners that are
#       #   currently registered by this extension.
#       #
#       def getHttpListeners; end
#       alias get_http_listeners getHttpListeners
#       alias http_listeners getHttpListeners
#
#       # This method is used to remove an HTTP listener that has been
#       # registered by the extension.
#       #
#       # @param [IHttpListener] listener The HTTP listener to be removed.
#       #
#       # @return [void]
#       def removeHttpListener(listener); end
#       alias remove_http_listener removeHttpListener
#
#       # This method is used to register a listener which will be notified of
#       # requests and responses being processed by the Proxy tool. Extensions
#       # can perform custom analysis or modification of these messages, and
#       # control in-UI message interception, by registering a proxy listener.
#       #
#       # @param [IProxyListener] listener An object created by the extension
#       #   that implements the {IProxyListener} interface.
#       #
#       # @return [void]
#       def registerProxyListener(listener); end
#       alias register_proxy_listener registerProxyListener
#
#       # This method is used to retrieve the Proxy listeners that are
#       # registered by the extension.
#       #
#       # @return [Array<IProxyListener>] A list of Proxy listeners that are
#       #   currently registered by this extension.
#       #
#       def getProxyListeners; end
#       alias get_proxy_listeners getProxyListeners
#       alias proxy_listeners getProxyListeners
#
#       # This method is used to remove a Proxy listener that has been
#       # registered by the extension.
#       #
#       # @param [IProxyListener] listener The Proxy listener to be removed.
#       #
#       # @return [void]
#       def removeProxyListener(listener); end
#       alias remove_proxy_listener removeProxyListener
#
#       # This method is used to register a listener which will be notified of
#       # new issues that are reported by the Scanner tool. Extensions can
#       # perform custom analysis or logging of Scanner issues by registering a
#       # Scanner listener.
#       #
#       # @param [IScannerListener] listener An object created by the extension
#       #   that implements the {IScannerListener} interface.
#       #
#       # @return [void]
#       def registerScannerListener(listener); end
#       alias register_scanner_listener registerScannerListener
#
#       # This method is used to retrieve the Scanner listeners that are
#       # registered by the extension.
#       #
#       # @return [Array<IScannerListener>] A list of Scanner listeners that
#       #   are currently registered by this extension.
#       #
#       def getScannerListeners; end
#       alias get_scanner_listeners getScannerListeners
#       alias scanner_listeners getScannerListeners
#
#       # This method is used to remove a Scanner listener that has been
#       # registered by the extension.
#       #
#       # @param [IScannerListener] listener The Scanner listener to be
#       #   removed.
#       #
#       # @return [void]
#       def removeScannerListener(listener); end
#       alias remove_scanner_listener removeScannerListener
#
#       # This method is used to register a listener which will be notified of
#       # changes to Burp's suite-wide target scope.
#       #
#       # @param [IScopeChangeListener] listener An object created by the
#       #   extension that implements the {IScopeChangeListener} interface.
#       #
#       # @return [void]
#       def registerScopeChangeListener(listener); end
#       alias register_scope_change_listener registerScopeChangeListener
#
#       # This method is used to retrieve the scope change listeners that are
#       # registered by the extension.
#       #
#       # @return [Array<IScopeChangeListener>] A list of scope change
#       #   listeners that are currently registered by this extension.
#       #
#       def getScopeChangeListeners; end
#       alias get_scope_change_listeners getScopeChangeListeners
#       alias scope_change_listeners getScopeChangeListeners
#
#       # This method is used to remove a scope change listener that has been
#       # registered by the extension.
#       #
#       # @param [IScopeChangeListener] listener The scope change listener to
#       #   be removed.
#       #
#       # @return [void]
#       def removeScopeChangeListener(listener); end
#       alias remove_scope_change_listener removeScopeChangeListener
#
#       # This method is used to register a factory for custom context menu
#       # items. When the user invokes a context menu anywhere within Burp, the
#       # factory will be passed details of the invocation event, and asked to
#       # provide any custom context menu items that should be shown.
#       #
#       # @param [IContextMenuFactory] factory An object created by the
#       #   extension that implements the {IContextMenuFactory} interface.
#       #
#       # @return [void]
#       def registerContextMenuFactory(factory); end
#       alias register_context_menu_factory registerContextMenuFactory
#
#       # This method is used to retrieve the context menu factories that are
#       # registered by the extension.
#       #
#       # @return [Array<IContextMenuFactory>] A list of context menu factories
#       #   that are currently registered by this extension.
#       #
#       def getContextMenuFactories; end
#       alias get_context_menu_factories getContextMenuFactories
#       alias context_menu_factories getContextMenuFactories
#
#       # This method is used to remove a context menu factory that has been
#       # registered by the extension.
#       #
#       # @param [IContextMenuFactory] factory The context menu factory to be
#       #   removed.
#       #
#       # @return [void]
#       def removeContextMenuFactory(factory); end
#       alias remove_context_menu_factory removeContextMenuFactory
#
#       # This method is used to register a factory for custom message editor
#       # tabs. For each message editor that already exists, or is subsequently
#       # created, * within Burp, the factory will be asked to provide a new
#       # instance of an {IMessageEditorTab} object, which can provide custom
#       # rendering or editing of HTTP messages.
#       #
#       # @param [IMessageEditorTabFactory] factory An object created by the
#       #   extension that implements the {IMessageEditorTabFactory} interface.
#       #
#       # @return [void]
#       def registerMessageEditorTabFactory(factory); end
#       alias register_message_editor_tab_factory registerMessageEditorTabFactory
#
#       # This method is used to retrieve the message editor tab factories that
#       # are registered by the extension.
#       #
#       # @return [Array<IMessageEditorTabFactory>] A list of message editor
#       #   tab factories that are currently registered by this extension.
#       #
#       def getMessageEditorTabFactories; end
#       alias get_message_editor_tab_factories getMessageEditorTabFactories
#       alias message_editor_tab_factories getMessageEditorTabFactories
#
#       # This method is used to remove a message editor tab factory that has
#       # been registered by the extension.
#       #
#       # @param [IMessageEditorTabFactory] factory The message editor tab
#       #   factory to be removed.
#       #
#       # @return [void]
#       def removeMessageEditorTabFactory(factory); end
#       alias remove_message_editor_tab_factory removeMessageEditorTabFactory
#
#       # This method is used to register a provider of Scanner insertion
#       # points. For each base request that is actively scanned, Burp will ask
#       # the provider to provide any custom scanner insertion points that are
#       # appropriate for the request.
#       #
#       # @param [IScannerInsertionPointProvider] provider An object created by
#       #   the extension that implements the {IScannerInsertionPointProvider}
#       #   interface.
#       #
#       # @return [void]
#       def registerScannerInsertionPointProvider(provider); end
#       alias register_scanner_insertion_point_provider registerScannerInsertionPointProvider
#
#       # This method is used to retrieve the Scanner insertion point providers
#       # that are registered by the extension.
#       #
#       # @return [Array<IScannerInsertionPointProvider>] A list of Scanner
#       #   insertion point providers that are currently registered by this
#       #   extension.
#       #
#       def getScannerInsertionPointProviders; end
#       alias get_scanner_insertion_point_providers getScannerInsertionPointProviders
#       alias scanner_insertion_point_providers getScannerInsertionPointProviders
#
#       # This method is used to remove a Scanner insertion point provider that
#       # has been registered by the extension.
#       #
#       # @param [IScannerInsertionPointProvider] provider The Scanner
#       #   insertion point provider to be removed.
#       #
#       # @return [void]
#       def removeScannerInsertionPointProvider(provider); end
#       alias remove_scanner_insertion_point_provider removeScannerInsertionPointProvider
#
#       # This method is used to register a custom Scanner check. When
#       # performing scanning, Burp will ask the check to perform active or
#       # passive scanning on the base request, and report any Scanner issues
#       # that are identified.
#       #
#       # @param [IScannerCheck] check An object created by the extension that
#       #   implements the {IScannerCheck} interface.
#       #
#       # @return [void]
#       #
#       def registerScannerCheck(check); end
#       alias register_scanner_check registerScannerCheck
#
#       # This method is used to retrieve the Scanner checks that are
#       # registered by the extension.
#       #
#       # @return [Array<IScannerCheck>] A list of Scanner checks that are
#       #   currently registered by this extension.
#       #
#       def getScannerChecks; end
#       alias get_scanner_checks getScannerChecks
#       alias scanner_checks getScannerChecks
#
#       # This method is used to remove a Scanner check that has been
#       # registered by the extension.
#       #
#       # @param [IScannerCheck] check The Scanner check to be removed.
#       #
#       # @return [void]
#       def removeScannerCheck(check); end
#       alias remove_scanner_check removeScannerCheck
#
#       # This method is used to register a factory for Intruder payloads. Each
#       # registered factory will be available within the Intruder UI for the
#       # user to select as the payload source for an attack. When this is
#       # selected, the factory will be asked to provide a new instance of an
#       # {IIntruderPayloadGenerator} object, which will be used to generate
#       # payloads for the attack.
#       #
#       # @param [IIntruderPayloadGeneratorFactory] factory An object created
#       #   by the extension that implements the
#       #   {IIntruderPayloadGeneratorFactory} interface.
#       #
#       # @return [void]
#       def registerIntruderPayloadGeneratorFactory(factory); end
#       alias register_intruder_payload_generator_factory registerIntruderPayloadGeneratorFactory
#
#       # This method is used to retrieve the Intruder payload generator
#       # factories that are registered by the extension.
#       #
#       # @return [Array<IIntruderPayloadGeneratorFactory>] A list of Intruder
#       #   payload generator factories that are currently registered by this
#       #   extension.
#       #
#       def getIntruderPayloadGeneratorFactories; end
#       alias get_intruder_payload_generator_factories getIntruderPayloadGeneratorFactories
#       alias intruder_payload_generator_factories getIntruderPayloadGeneratorFactories
#
#       # This method is used to remove an Intruder payload generator factory
#       # that has been registered by the extension.
#       #
#       # @param [IIntruderPayloadGeneratorFactory] factory The Intruder
#       #   payload generator factory to be removed.
#       #
#       # @return [void]
#       def removeIntruderPayloadGeneratorFactory(factory); end
#       alias remove_intruder_payload_generator_factory removeIntruderPayloadGeneratorFactory
#
#       # This method is used to register a custom Intruder payload processor.
#       # Each registered processor will be available within the Intruder UI
#       # for the user to select as the action for a payload processing rule.
#       #
#       # @param [IIntruderPayloadProcessor] processor An object created by the
#       #   extension that implements the {IIntruderPayloadProcessor}
#       #   interface.
#       #
#       # @return [void]
#       def registerIntruderPayloadProcessor(processor); end
#       alias register_intruder_payload_processor registerIntruderPayloadProcessor
#
#       # This method is used to retrieve the Intruder payload processors that
#       # are registered by the extension.
#       #
#       # @return [Array<IIntruderPayloadProcessor>] A list of Intruder payload
#       #   processors that are currently registered by this extension.
#       #
#       def getIntruderPayloadProcessors; end
#       alias get_intruder_payload_processors getIntruderPayloadProcessors
#       alias intruder_payload_processors getIntruderPayloadProcessors
#
#       # This method is used to remove an Intruder payload processor that has
#       # been registered by the extension.
#       #
#       # @param [IIntruderPayloadProcessor] processor The Intruder payload
#       #   processor to be removed.
#       #
#       # @return [void]
#       def removeIntruderPayloadProcessor(processor); end
#       alias remove_intruder_payload_processor removeIntruderPayloadProcessor
#
#       # This method is used to register a custom session handling action.
#       # Each registered action will be available within the session handling
#       # rule UI for the user to select as a rule action. Users can choose to
#       # invoke an action directly in its own right, or following execution of
#       # a macro.
#       #
#       # @param [ISessionHandlingAction] action An object created by the
#       #   extension that implements the {ISessionHandlingAction} interface.
#       #
#       # @return [void]
#       def registerSessionHandlingAction(action); end
#       alias register_session_handling_action registerSessionHandlingAction
#
#       # This method is used to retrieve the session handling actions that are
#       # registered by the extension.
#       #
#       # @return [Array<ISessionHandlingAction>] A list of session handling
#       #   actions that are currently registered by this extension.
#       #
#       def getSessionHandlingActions; end
#       alias get_session_handling_actions getSessionHandlingActions
#       alias session_handling_actions getSessionHandlingActions
#
#       # This method is used to remove a session handling action that has been
#       # registered by the extension.
#       #
#       # @param [ISessionHandlingAction] action The extension session handling
#       #   action to be removed.
#       #
#       # @return [void]
#       def removeSessionHandlingAction(action); end
#       alias remove_session_handling_action removeSessionHandlingAction
#
#       # This method is used to unload the extension from Burp Suite.
#       #
#       # @return [void]
#       def unloadExtension; end
#       alias unload_extension unloadExtension
#
#       # This method is used to add a custom tab to the main Burp Suite
#       # window.
#       #
#       # @param [ITab] tab An object created by the extension that implements
#       #   the {ITab} interface.
#       #
#       # @return [void]
#       def addSuiteTab(tab); end
#       alias add_suite_tab addSuiteTab
#
#       # This method is used to remove a previously-added tab from the main
#       # Burp Suite window.
#       #
#       # @param [ITab] tab An object created by the extension that implements
#       #   the {ITab} interface.
#       #
#       # @return [void]
#       def removeSuiteTab(tab); end
#       alias remove_suite_tab removeSuiteTab
#
#       # This method is used to customize UI components in line with Burp's UI
#       # style, including font size, colors, table line spacing, etc. The
#       # action is performed recursively on any child components of the
#       # passed-in component.
#       #
#       # @param [Component] component The UI component to be customized.
#       #
#       # @return [void]
#       def customizeUiComponent(component); end
#       alias customize_ui_component customizeUiComponent
#
#       # This method is used to create a new instance of Burp's HTTP message
#       # editor, for the extension to use in its own UI.
#       #
#       # @param [IMessageEditorController] controller An object created by the
#       #   extension that implements the {IMessageEditorController} interface.
#       #   This parameter is optional and may be +null+. If it is provided,
#       #   then the message editor will query the controller when required to
#       #   obtain details about the currently displayed message, including the
#       #   {IHttpService} for the message, and the associated request or
#       #   response message. If a controller is not provided, then the message
#       #   editor will not support context menu actions, such as sending
#       #   requests to other Burp tools.
#       # @param [boolean] editable Indicates whether the editor created should
#       #   be editable, * or used only for message viewing.
#       #
#       # @return [IMessageEditor] An object that implements the
#       #   {IMessageEditor} interface, and which the extension can use in its
#       #   own UI.
#       #
#       def createMessageEditor(controller, editable); end
#       alias create_message_editor createMessageEditor
#
#       # This method returns the command line arguments that were passed to
#       # Burp on startup.
#       #
#       # @return [Array<String>] The command line arguments that were passed
#       #   to Burp on startup.
#       #
#       def getCommandLineArguments; end
#       alias get_command_line_arguments getCommandLineArguments
#       alias command_line_arguments getCommandLineArguments
#
#       # This method is used to save configuration settings for the extension
#       # in a persistent way that survives reloads of the extension and of
#       # Burp Suite. Saved settings can be retrieved using the method
#       # {#loadExtensionSetting}.
#       #
#       # @param [String] name The name of the setting.
#       # @param [String] value The value of the setting. If this value is
#       #   +nil+ then any existing setting with the specified name will be
#       #   removed.
#       #
#       # @return [void]
#       def saveExtensionSetting(name, value); end
#       alias save_extension_setting saveExtensionSetting
#
#       # This method is used to load configuration settings for the extension
#       # that were saved using the method {#saveExtensionSetting}.
#       #
#       # @param [String] name The name of the setting.
#       #
#       # @return [String] The value of the setting, or +nil+ if no value is
#       #   set.
#       #
#       def loadExtensionSetting(name); end
#       alias load_extension_setting loadExtensionSetting
#
#       # This method is used to create a new instance of Burp's plain text
#       # editor, * for the extension to use in its own UI.
#       #
#       # @return [ITextEditor] An object that implements the {ITextEditor}
#       #   interface, * and which the extension can use in its own UI.
#       #
#       def createTextEditor; end
#       alias create_text_editor createTextEditor
#
#       # This method can be used to send an HTTP request to the Burp Repeater
#       # tool. The request will be displayed in the user interface, but will
#       # not be issued until the user initiates this action.
#       #
#       # @param [String] host The hostname of the remote HTTP server.
#       # @param [int] port The port of the remote HTTP server.
#       # @param [boolean] useHttps Flags whether the protocol is HTTPS or
#       #   HTTP.
#       # @param [Array<byte>] request The full HTTP request.
#       # @param [String] tabCaption An optional caption which will appear on
#       #   the Repeater tab containing the request. If this value is +nil+
#       #   then a default tab index will be displayed.
#       #
#       # @return [void]
#       def sendToRepeater(host, port, useHttps, request, tabCaption); end
#       alias send_to_repeater sendToRepeater
#
#       # This method can be used to send an HTTP request to the Burp Intruder
#       # tool. The request will be displayed in the user interface, and
#       # markers for attack payloads will be placed into default locations
#       # within the request.
#       #
#       # @param [String] host The hostname of the remote HTTP server.
#       # @param [int] port The port of the remote HTTP server.
#       # @param [boolean] useHttps Flags whether the protocol is HTTPS or
#       #   HTTP.
#       # @param [Array<byte>] request The full HTTP request.
#       #
#       # @return [void]
#       def sendToIntruder(host, port, useHttps, request); end
#       alias send_to_intruder sendToIntruder
#
#       # This method can be used to send an HTTP request to the Burp Intruder
#       # tool. The request will be displayed in the user interface, and
#       # markers for attack payloads will be placed into the specified
#       # locations within the request.
#       #
#       # @param [String] host The hostname of the remote HTTP server.
#       # @param [int] port The port of the remote HTTP server.
#       # @param [boolean] useHttps Flags whether the protocol is HTTPS or
#       #   HTTP.
#       # @param [Array<byte>] request The full HTTP request.
#       # @param [Array<Array<int>>] payloadPositionOffsets A list of index
#       #   pairs representing the payload positions to be used. Each item in
#       #   the list must be an int[2] array containing the start and end
#       #   offsets for the payload position.
#       #
#       # @return [void]
#       def sendToIntruder(host, port, useHttps, request, payloadPositionOffsets); end
#       alias send_to_intruder sendToIntruder
#
#       # This method can be used to send data to the Comparer tool.
#       #
#       # @param [Array<byte>] data The data to be sent to Comparer.
#       #
#       # @return [void]
#       def sendToComparer(data); end
#       alias send_to_comparer sendToComparer
#
#       # This method can be used to send a seed URL to the Burp Spider tool.
#       # If the URL is not within the current Spider scope, the user will be
#       # asked if they wish to add the URL to the scope. If the Spider is not
#       # currently running, it will be started. The seed URL will be
#       # requested, and the Spider will process the application's response in
#       # the normal way.
#       #
#       # @param [java.net.URL] url The new seed URL to begin spidering from.
#       #
#       # @return [void]
#       def sendToSpider(url); end
#       alias send_to_spider sendToSpider
#
#       # This method can be used to send an HTTP request to the Burp Scanner
#       # tool to perform an active vulnerability scan. If the request is not
#       # within the current active scanning scope, the user will be asked if
#       # they wish to proceed with the scan.
#       #
#       # @param [String] host The hostname of the remote HTTP server.
#       # @param [int] port The port of the remote HTTP server.
#       # @param [boolean] useHttps Flags whether the protocol is HTTPS or
#       #   HTTP.
#       # @param [Array<byte>] request The full HTTP request.
#       #
#       # @return [IScanQueueItem] The resulting scan queue item.
#       #
#       def doActiveScan(host, port, useHttps, request); end
#       alias do_active_scan doActiveScan
#
#       # This method can be used to send an HTTP request to the Burp Scanner
#       # tool to perform an active vulnerability scan, based on a custom list
#       # of insertion points that are to be scanned. If the request is not
#       # within the current active scanning scope, the user will be asked if
#       # they wish to proceed with the scan.
#       #
#       # @param [String] host The hostname of the remote HTTP server.
#       # @param [int] port The port of the remote HTTP server.
#       # @param [boolean] useHttps Flags whether the protocol is HTTPS or
#       #   HTTP.
#       # @param [Array<byte>] request The full HTTP request.
#       # @param [Array<Array<int>>] insertionPointOffsets A list of index
#       #   pairs representing the positions of the insertion points that
#       #   should be scanned. Each item in the list must be an int[2] array
#       #   containing the start and end offsets for the insertion point.
#       #
#       # @return [IScanQueueItem] The resulting scan queue item.
#       #
#       def doActiveScan(host, port, useHttps, request, insertionPointOffsets); end
#       alias do_active_scan doActiveScan
#
#       # This method can be used to send an HTTP request to the Burp Scanner
#       # tool to perform a passive vulnerability scan.
#       #
#       # @param [String] host The hostname of the remote HTTP server.
#       # @param [int] port The port of the remote HTTP server.
#       # @param [boolean] useHttps Flags whether the protocol is HTTPS or
#       #   HTTP.
#       # @param [Array<byte>] request The full HTTP request.
#       # @param [Array<byte>] response The full HTTP response.
#       #
#       # @return [void]
#       def doPassiveScan(host, port, useHttps, request, response); end
#       alias do_passive_scan doPassiveScan
#
#       # This method can be used to issue HTTP requests and retrieve their
#       # responses.
#       #
#       # @param [IHttpService] httpService The HTTP service to which the
#       #   request should be sent.
#       # @param [Array<byte>] request The full HTTP request.
#       #
#       # @return [IHttpRequestResponse] An object that implements the
#       #   {IHttpRequestResponse} interface, and which the extension can query
#       #   to obtain the details of the response.
#       #
#       def makeHttpRequest(httpService, request); end
#       alias make_http_request makeHttpRequest
#
#       # This method can be used to issue HTTP requests and retrieve their
#       # responses.
#       #
#       # @param [String] host The hostname of the remote HTTP server.
#       # @param [int] port The port of the remote HTTP server.
#       # @param [boolean] useHttps Flags whether the protocol is HTTPS or
#       #   HTTP.
#       # @param [Array<byte>] request The full HTTP request.
#       #
#       # @return [Array<byte>] The full response retrieved from the remote
#       #   server.
#       #
#       def makeHttpRequest(host, port, useHttps, request); end
#       alias make_http_request makeHttpRequest
#
#       # This method can be used to query whether a specified URL is within
#       # the current Suite-wide scope.
#       #
#       # @param [java.net.URL] url The URL to query.
#       #
#       # @return [boolean] Returns +true+ if the URL is within the current
#       #   Suite-wide scope.
#       #
#       def isInScope(url); end
#       alias is_in_scope isInScope
#       alias in_scope? isInScope
#
#       # This method can be used to include the specified URL in the
#       # Suite-wide scope.
#       #
#       # @param [java.net.URL] url The URL to include in the Suite-wide scope.
#       #
#       # @return [void]
#       def includeInScope(url); end
#       alias include_in_scope includeInScope
#
#       # This method can be used to exclude the specified URL from the
#       # Suite-wide scope.
#       #
#       # @param [java.net.URL] url The URL to exclude from the Suite-wide
#       #   scope.
#       #
#       # @return [void]
#       def excludeFromScope(url); end
#       alias exclude_from_scope excludeFromScope
#
#       # This method can be used to display a specified message in the Burp
#       # Suite alerts tab.
#       #
#       # @param [String] message The alert message to display.
#       #
#       # @return [void]
#       def issueAlert(message); end
#       alias issue_alert issueAlert
#
#       # This method returns details of all items in the Proxy history.
#       #
#       # @return [Array<IHttpRequestResponse>] The contents of the Proxy
#       #   history.
#       #
#       def getProxyHistory; end
#       alias get_proxy_history getProxyHistory
#       alias proxy_history getProxyHistory
#
#       # This method returns details of items in the site map.
#       #
#       # @param [String] urlPrefix This parameter can be used to specify a URL
#       #   prefix, in order to extract a specific subset of the site map. The
#       #   method performs a simple case-sensitive text match, returning all
#       #   site map items whose URL begins with the specified prefix. If this
#       #   parameter is null, the entire site map is returned.
#       #
#       # @return [Array<IHttpRequestResponse>] Details of items in the site
#       #   map.
#       #
#       def getSiteMap(urlPrefix); end
#       alias get_site_map getSiteMap
#       alias site_map getSiteMap
#
#       # This method returns all of the current scan issues for URLs matching
#       # the specified literal prefix.
#       #
#       # @param [String] urlPrefix This parameter can be used to specify a URL
#       #   prefix, in order to extract a specific subset of scan issues. The
#       #   method performs a simple case-sensitive text match, returning all
#       #   scan issues whose URL begins with the specified prefix. If this
#       #   parameter is null, all issues are returned.
#       #
#       # @return [Array<IScanIssue>] Details of the scan issues.
#       #
#       def getScanIssues(urlPrefix); end
#       alias get_scan_issues getScanIssues
#       alias scan_issues getScanIssues
#
#       # This method is used to generate a report for the specified Scanner
#       # issues. The report format can be specified. For all other reporting
#       # options, the default settings that appear in the reporting UI wizard
#       # are used.
#       #
#       # @param [String] format The format to be used in the report. Accepted
#       #   values are HTML and XML.
#       # @param [Array<IScanIssue>] issues The Scanner issues to be reported.
#       # @param [java.io.File] file The file to which the report will be
#       #   saved.
#       #
#       # @return [void]
#       def generateScanReport(format, issues, file); end
#       alias generate_scan_report generateScanReport
#
#       # This method is used to retrieve the contents of Burp's session
#       # handling cookie jar. Extensions that provide an
#       # {ISessionHandlingAction} can query and update the cookie jar in order
#       # to handle unusual session handling mechanisms.
#       #
#       # @return [Array<ICookie>] A list of {ICookie} objects representing the
#       #   contents of Burp's session handling cookie jar.
#       #
#       def getCookieJarContents; end
#       alias get_cookie_jar_contents getCookieJarContents
#       alias cookie_jar_contents getCookieJarContents
#
#       # This method is used to update the contents of Burp's session handling
#       # cookie jar. Extensions that provide an {ISessionHandlingAction} can
#       # query and update the cookie jar in order to handle unusual session
#       # handling mechanisms.
#       #
#       # @param [ICookie] cookie An {ICookie} object containing details of the
#       #   cookie to be updated. If the cookie jar already contains a cookie
#       #   that matches the specified domain and name, then that cookie will
#       #   be updated with the new value and expiration, unless the new value
#       #   is +nil+, in which case the cookie will be removed. If the cookie
#       #   jar does not already contain a cookie that matches the specified
#       #   domain and name, then the cookie will be added.
#       #
#       # @return [void]
#       def updateCookieJar(cookie); end
#       alias update_cookie_jar updateCookieJar
#
#       # This method can be used to add an item to Burp's site map with the
#       # specified request/response details. This will overwrite the details
#       # of any existing matching item in the site map.
#       #
#       # @param [IHttpRequestResponse] item Details of the item to be added to
#       #   the site map
#       #
#       # @return [void]
#       def addToSiteMap(item); end
#       alias add_to_site_map addToSiteMap
#
#       # This method can be used to restore Burp's state from a specified
#       # saved state file. This method blocks until the restore operation is
#       # completed, * and must not be called from the event dispatch thread.
#       #
#       # @param [java.io.File] file The file containing Burp's saved state.
#       #
#       # @return [void]
#       def restoreState(file); end
#       alias restore_state restoreState
#
#       # This method can be used to save Burp's state to a specified file.
#       # This method blocks until the save operation is completed, and must
#       # not be called from the event dispatch thread.
#       #
#       # @param [java.io.File] file The file to save Burp's state in.
#       #
#       # @return [void]
#       def saveState(file); end
#       alias save_state saveState
#
#       # This method causes Burp to save all of its current configuration as a
#       # Map of name/value Strings.
#       #
#       # @return [Map<String, String>] A Map of name/value Strings reflecting
#       #   Burp's current configuration.
#       #
#       def saveConfig; end
#       alias save_config saveConfig
#
#       # This method causes Burp to load a new configuration from the Map of
#       # name/value Strings provided. Any settings not specified in the Map
#       # will be restored to their default values. To selectively update only
#       # some settings and leave the rest unchanged, you should first call
#       # {#saveConfig} to obtain Burp's current configuration, modify the
#       # relevant items in the Map, and then call {#loadConfig} with the same
#       # Map.
#       #
#       # @param [Map<String, String>] config A map of name/value Strings to
#       #   use as Burp's new configuration.
#       #
#       # @return [void]
#       def loadConfig(Map<String, config); end
#       alias load_config loadConfig
#
#       # This method sets the master interception mode for Burp Proxy.
#       #
#       # @param [boolean] enabled Indicates whether interception of Proxy
#       #   messages should be enabled.
#       #
#       # @return [void]
#       def setProxyInterceptionEnabled(enabled); end
#       alias set_proxy_interception_enabled setProxyInterceptionEnabled
#       alias proxy_interception_enabled= setProxyInterceptionEnabled
#
#       # This method retrieves information about the version of Burp in which
#       # the extension is running. It can be used by extensions to dynamically
#       # adjust their behavior depending on the functionality and APIs
#       # supported by the current version.
#       #
#       # @return [Array<String>] An array of Strings comprised of: the product
#       #   name (e.g. Burp Suite Professional), the major version (e.g. 1.5),
#       #   the minor version (e.g. 03)
#       #
#       def getBurpVersion; end
#       alias get_burp_version getBurpVersion
#       alias burp_version getBurpVersion
#
#       # This method retrieves the absolute path name of the file from which
#       # the current extension was loaded.
#       #
#       # @return [String] The absolute path name of the file from which the
#       #   current extension was loaded.
#       #
#       def getExtensionFilename; end
#       alias get_extension_filename getExtensionFilename
#       alias extension_filename getExtensionFilename
#
#       # This method determines whether the current extension was loaded as a
#       # BApp (a Burp App from the BApp Store).
#       #
#       # @return [boolean] Returns true if the current extension was loaded as
#       #   a BApp.
#       #
#       def isExtensionBapp; end
#       alias is_extension_bapp isExtensionBapp
#       alias extension_bapp? isExtensionBapp
#
#       # This method can be used to shut down Burp programmatically, with an
#       # optional prompt to the user. If the method returns, the user canceled
#       # the shutdown prompt.
#       #
#       # @param [boolean] promptUser Indicates whether to prompt the user to
#       #   confirm the shutdown.
#       #
#       # @return [void]
#       def exitSuite(promptUser); end
#       alias exit_suite exitSuite
#
#       # This method is used to create a temporary file on disk containing the
#       # provided data. Extensions can use temporary files for long-term
#       # storage of runtime data, avoiding the need to retain that data in
#       # memory.
#       #
#       # @param [Array<byte>] buffer The data to be saved to a temporary file.
#       #
#       # @return [ITempFile] An object that implements the {ITempFile}
#       #   interface.
#       #
#       def saveToTempFile(buffer); end
#       alias save_to_temp_file saveToTempFile
#
#       # This method is used to save the request and response of an
#       # {IHttpRequestResponse} object to temporary files, so that they are no
#       # longer held in memory. Extensions can used this method to convert
#       # {IHttpRequestResponse} objects into a form suitable for long-term
#       # storage.
#       #
#       # @param [IHttpRequestResponse] httpRequestResponse The
#       #   {IHttpRequestResponse} object whose request and response messages
#       #   are to be saved to temporary files.
#       #
#       # @return [IHttpRequestResponsePersisted] An object that implements the
#       #   {IHttpRequestResponsePersisted} interface.
#       #
#       def saveBuffersToTempFiles(httpRequestResponse); end
#       alias save_buffers_to_temp_files saveBuffersToTempFiles
#
#       # This method is used to apply markers to an HTTP request or response,
#       # at offsets into the message that are relevant for some particular
#       # purpose. Markers are used in various situations, such as specifying
#       # Intruder payload positions, Scanner insertion points, and highlights
#       # in Scanner issues.
#       #
#       # @param [IHttpRequestResponse] httpRequestResponse The
#       #   {IHttpRequestResponse} object to which the markers should be
#       #   applied.
#       # @param [Array<Array<int>>] requestMarkers A list of index pairs
#       #   representing the offsets of markers to be applied to the request
#       #   message. Each item in the list must be an int[2] array containing
#       #   the start and end offsets for the marker. The markers in the list
#       #   should be in sequence and not overlapping. This parameter is
#       #   optional and may be +nil+ if no request markers are required.
#       # @param [Array<Array<int>>] responseMarkers A list of index pairs
#       #   representing the offsets of markers to be applied to the response
#       #   message. Each item in the list must be an int[2] array containing
#       #   the start and end offsets for the marker. The markers in the list
#       #   should be in sequence and not overlapping. This parameter is
#       #   optional and may be +nil+ if no response markers are required.
#       #
#       # @return [IHttpRequestResponseWithMarkers] An object that implements
#       #   the {IHttpRequestResponseWithMarkers} interface.
#       #
#       def applyMarkers(httpRequestResponse, requestMarkers, responseMarkers); end
#       alias apply_markers applyMarkers
#
#       # This method is used to obtain the descriptive name for the Burp tool
#       # identified by the tool flag provided.
#       #
#       # @param [int] toolFlag A flag identifying a Burp tool (+TOOL_PROXY+,
#       #   +TOOL_SCANNER+, etc.). Tool flags are defined within this
#       #   interface.
#       #
#       # @return [String] The descriptive name for the specified tool.
#       #
#       def getToolName(toolFlag); end
#       alias get_tool_name getToolName
#       alias tool_name getToolName
#
#       # This method is used to register a new Scanner issue. <b>Note:</b>
#       # Wherever possible, extensions should implement custom Scanner checks
#       # using {IScannerCheck} and report issues via those checks, so as to
#       # integrate with Burp's user-driven workflow, and ensure proper
#       # consolidation of duplicate reported issues. This method is only
#       # designed for tasks outside of the normal testing workflow, such as
#       # importing results from other scanning tools.
#       #
#       # @param [IScanIssue] issue An object created by the extension that
#       #   implements the {IScanIssue} interface.
#       #
#       # @return [void]
#       def addScanIssue(issue); end
#       alias add_scan_issue addScanIssue
#
#       # This method parses the specified request and returns details of each
#       # request parameter.
#       #
#       # @param [Array<byte>] request The request to be parsed.
#       #
#       # @return [Array<String>[]] An array of:
#       #   +Array<String>{name,value,type}+ containing details of the
#       #   parameters contained within the request.
#       #
#       # @deprecated Use {IExtensionHelpers#analyzeRequest} instead.
#       #
#       def getParameters(request); end
#       alias get_parameters getParameters
#       alias parameters getParameters
#
#       # This method parses the specified request and returns details of each
#       # HTTP header.
#       #
#       # @param [Array<byte>] message The request to be parsed.
#       #
#       # @return [Array<String>] An array of HTTP headers.
#       #
#       # @deprecated Use {IExtensionHelpers#analyzeRequest} or
#       #   {IExtensionHelpers#analyzeResponse} instead.
#       #
#       def getHeaders(message); end
#       alias get_headers getHeaders
#       alias headers getHeaders
#
#       # This method can be used to register a new menu item which will appear
#       # on the various context menus that are used throughout Burp Suite to
#       # handle user-driven actions.
#       #
#       # @param [String] menuItemCaption The caption to be displayed on the
#       #   menu item.
#       # @param [IMenuItemHandler] menuItemHandler The handler to be invoked
#       #   when the user clicks on the menu item.
#       #
#       # @return [void]
#       #
#       # @deprecated Use {#registerContextMenuFactory} instead.
#       #
#       def registerMenuItem(menuItemCaption, menuItemHandler); end
#       alias register_menu_item registerMenuItem
#     end
#   end

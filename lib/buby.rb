require 'pp'
require 'uri'
require "buby.jar"
require 'buby/implants'

import 'burp.BurpExtender'

# Buby is a mash-up of the commercial security testing web proxy PortSwigger 
# Burp Suite(tm) allowing you to add scripting to Burp. Burp is driven from 
# and tied to JRuby with a Java extension using the BurpExtender API.
#
# The Buby class is an abstract implementation of a BurpExtender ruby handler. 
# Included are several abstract event handlers used from the BurpExtender
# java implementation:
# * evt_extender_init
# * evt_proxy_message
# * evt_command_line_args (removed in 1.5.01)
# * evt_register_callbacks
# * evt_application_closing (deprecated)
# * evt_extension_unloaded
#
# Buby also supports the newer event handlers available in Burp 1.2.09 and up:
# * evt_http_message
# * evt_scan_issue
#
#
# This class also exposes several methods to access Burp functionality 
# and user interfaces through the IBurpExtenderCallbacks interface 
# (note, several abbreviated aliases also exist for each):
# * doActiveScan
# * doPassiveScan
# * excludeFromScope
# * includeInScope
# * isInScope
# * issueAlert
# * makeHttpRequest
# * sendToIntruder
# * sendToRepeater
# * sendToSpider
#
# Buby also provides front-end ruby methods for the various callback methods 
# supported by Burp. New callbacks have been cropping up in newer Burp versions
# frequently. 
# 
# Available since Burp 1.2.09:
# * getProxyHistory
# * getSiteMap
# * restoreState
# * saveState
# * getParameters
# * getHeaders
#
# Available since Burp 1.2.15:
# * getScanIssues
#
# Available since Burp 1.2.17:
# * exitSuite
#
# If you wish to access any of the IBurpExtenderCallbacks methods directly. 
# You can use 'burp_callbacks' to obtain a reference.
#
# Credit:
# * Burp and Burp Suite are trade-marks of PortSwigger Ltd.
#     Copyright 2011 PortSwigger Ltd. All rights reserved.
#     See http://portswigger.net for license terms.
#
# * This ruby library and the accompanying BurpExtender.java implementation 
#   were written by Eric Monti @ Matasano Security. 
#
#   Matasano claims no professional or legal affiliation with PortSwigger LTD. 
#   nor do we sell or officially endorse any of their products.
#
#   However, this author would like to express his personal and professional 
#   respect and appreciation for their making available the BurpExtender 
#   extension API. The availability of this interface in an already great tool
#   goes a long way to make Burp Suite a truly first-class application.
#
# * Forgive the name. It won out over "Burb" and "BurpRub". It's just easier 
#   to type and say out-loud. Mike Tracy gets full credit as official 
#   Buby-namer.
#
class Buby
  autoload :ContextMenuFactory, 'buby/context_menu_factory'
  autoload :Cookie, 'buby/cookie'
  autoload :HttpListener, 'buby/http_listener'
  autoload :IntruderPayloadGenerator, 'buby/intruder_payload_generator'
  autoload :IntruderPayloadGeneratorFactory, 'buby/intruder_payload_generator_factory'
  autoload :IntruderPayloadProcessor, 'buby/intruder_payload_processor'
  autoload :MessageEditorController, 'buby/message_editor_controller'
  autoload :MessageEditorTab, 'buby/message_editor_tab'
  autoload :MessageEditorTabFactory, 'buby/message_editor_tab_factory'
  autoload :Parameter, 'buby/parameter'
  autoload :Version, 'buby/version'

  # @deprecated moving to proper version module
  VERSION = Buby::Version::STRING
  
  # latest tested version of burp
  COMPAT_VERSION = '1.5.04'

  # :stopdoc:
  # @deprecated to be removed next version
  # @api private
  LIBPATH = ::File.expand_path(::File.dirname(__FILE__)) + ::File::SEPARATOR

  # @deprecated to be removed next version
  # @api private
  PATH = ::File.dirname(LIBPATH) + ::File::SEPARATOR
  # :startdoc:

  def initialize(other=nil)
    if other
      raise TypeError, "argument must be another kind of Buby, got #{other.class}" unless other.is_a? Buby
      @burp_extender = other.burp_extender
      @burp_callbacks = other.burp_callbacks
    end
  end

  # Makes this handler the active Ruby handler object for the BurpExtender
  # Java runtime. (there can be only one!)
  def activate!
    Java::Burp::BurpExtender.set_handler(self)
  end

  # Returns the internal reference to the BurpExtender instance. This
  # reference gets set from Java through the evt_extender_init method.
  def burp_extender; @burp_extender; end

  # Returns the internal reference to the IBupExtenderCallbacks instance.
  # This reference gets set from Java through the evt_register_callbacks
  # method. It is exposed to allow you to access the IBurpExtenderCallbacks 
  # instance directly if you so choose.
  def burp_callbacks; @burp_callbacks; end

  # Internal method to check for the existence of the burp_callbacks reference
  # before doing anything with it.
  def _check_cb
    @burp_callbacks or raise "Burp callbacks have not been set"
  end

  # Send an HTTP request to the Burp Scanner tool to perform an active 
  # vulnerability scan.
  #  * host = The hostname of the remote HTTP server.
  #  * port = The port of the remote HTTP server.
  #  * https = Flags whether the protocol is HTTPS or HTTP.
  #  * req  = The full HTTP request. (String or Java bytes[])
  #  * ip_off = A list of index pairs representing the
  #  * positions of the insertion points that should be scanned. Each item in
  #  * the list must be an int[2] array containing the start and end offsets
  #  * for the insertion point. *1.4+* only
  #
  def doActiveScan(host, port, https, req, ip_off)
    req = req.to_java_bytes if req.is_a? String
    getBurpVersion ? _check_cb.doActiveScan(host, port, https, req, ip_off) : _check_cb.doActiveScan(host, port, https, req)
  end
  alias do_active_scan doActiveScan
  alias active_scan doActiveScan

  # Send an HTTP request and response to the Burp Scanner tool to perform a 
  # passive vulnerability scan.
  #  * host = The hostname of the remote HTTP server.
  #  * port = The port of the remote HTTP server.
  #  * https = Flags whether the protocol is HTTPS or HTTP.
  #  * req  = The full HTTP request. (String or Java bytes[])
  #  * rsp  = The full HTTP response. (String or Java bytes[])
  def doPassiveScan(host, port, https, req, rsp)
    req = req.to_java_bytes if req.is_a? String
    rsp = rsp.to_java_bytes if rsp.is_a? String
    _check_cb.doPassiveScan(host, port, https, req, rsp)
  end
  alias do_passive_scan doPassiveScan
  alias passive_scan doPassiveScan

  # Exclude the specified URL from the Suite-wide scope.
  #  * url = The URL to exclude from the Suite-wide scope.
  def excludeFromScope(url)
    url = java.net.URL.new(url) if url.is_a? String
    _check_cb.excludeFromScope(url)
  end
  alias exclude_from_scope excludeFromScope
  alias exclude_scope excludeFromScope

  # Include the specified URL in the Suite-wide scope.
  #  * url = The URL to exclude in the Suite-wide scope.
  def includeInScope(url)
    url = java.net.URL.new(url) if url.is_a? String
    _check_cb.includeInScope(url)
  end
  alias include_in_scope includeInScope 
  alias include_scope includeInScope 

  # Query whether a specified URL is within the current Suite-wide scope.
  #  * url = The URL to query
  #
  # Returns: true / false
  def isInScope(url)
    url = java.net.URL.new(url) if url.is_a? String
    _check_cb.isInScope(url)
  end
  alias is_in_scope isInScope
  alias in_scope? isInScope

  # Display a message in the Burp Suite alerts tab.
  #  * msg =  The alert message to display.
  def issueAlert(msg)
    _check_cb.issueAlert(msg.to_s)
  end
  alias issue_alert issueAlert
  alias alert issueAlert

  # Issue an arbitrary HTTP request and retrieve its response
  #  * host  = The hostname of the remote HTTP server.
  #  * port  = The port of the remote HTTP server.
  #  * https = Flags whether the protocol is HTTPS or HTTP.
  #  * req   = The full HTTP request. (String or Java bytes[])
  #
  # also may be called with new IHttpService as an argument
  #  * service = IHttpService object with host, port, etc.
  #  * request = request string
  # @return The full response retrieved from the remote server.
  #
  def makeHttpRequest(*args)
    ret = case args.size
    when 2
      service, req = args
      req = req.to_java_bytes if req.is_a? String
      _check_and_callback(:makeHttpRequst, service, req)
    when 4
      host, port, https, req = args
      req = req.to_java_bytes if req.is_a? String
      _check_cb.makeHttpRequest(host, port, https, req)
    else
      raise ArgumentError
    end
    String.from_java_bytes(ret)
  end
  alias make_http_request makeHttpRequest
  alias make_request makeHttpRequest

  # Send an HTTP request to the Burp Intruder tool
  #  * host  = The hostname of the remote HTTP server.
  #  * port  = The port of the remote HTTP server.
  #  * https = Flags whether the protocol is HTTPS or HTTP.
  #  * req   = The full HTTP request.  (String or Java bytes[])
  #  * ip_off = A list of index pairs representing the
  #  * positions of the insertion points that should be scanned. Each item in
  #  * the list must be an int[2] array containing the start and end offsets
  #  * for the insertion point. *1.4.04+* only
  #  * 
  def sendToIntruder(host, port, https, req, ip_off)
    req = req.to_java_bytes if req.is_a? String
    if self.getBurpVersion.to_a[1..-1].join(".") < "1.4.04"
      _check_cb.sendToIntruder(host, port, https, req)
    else
      _check_cb.sendToIntruder(host, port, https, req, ip_off)
    end
  end
  alias send_to_intruder sendToIntruder
  alias intruder sendToIntruder

  # Send an HTTP request to the Burp Repeater tool.
  #  * host  = The hostname of the remote HTTP server.
  #  * port  = The port of the remote HTTP server.
  #  * https = Flags whether the protocol is HTTPS or HTTP.
  #  * req   = The full HTTP request. (String or Java bytes[])
  #  * tab   = The tab caption displayed in Repeater. (default: auto-generated)
  def sendToRepeater(host, port, https, req, tab=nil)
    req = req.to_java_bytes if req.is_a? String
    _check_cb.sendToRepeater(host, port, https, req, tab)
  end
  alias send_to_repeater sendToRepeater
  alias repeater sendToRepeater

  # Send a seed URL to the Burp Spider tool.
  #  * url = The new seed URL to begin spidering from.
  def sendToSpider(url)
    url = java.net.URL.new(url) if url.is_a? String
    _check_cb.sendToSpider(url)
  end
  alias send_to_spider sendToSpider
  alias spider sendToSpider

  # This method is a __send__ callback gate for the IBurpExtenderCallbacks
  # reference. It first checks to see if a method is available before calling
  # with the specified arguments, and raises an exception if it is unavailable.
  #
  # * meth = string or symbol name of method
  # * args = variable length array of arguments to pass to meth
  def _check_and_callback(meth, *args, &block)
    cb = _check_cb
    unless cb.respond_to?(meth)
      raise "#{meth} is not available in your version of Burp"
    end
    cb.__send__ meth, *args, &block
  end


  # Returns a Java array of IHttpRequestResponse objects pulled directly from 
  # the Burp proxy history.
  # @todo Bring IHttpRequestResponse helper up to date
  def getProxyHistory
    HttpRequestResponseList.new(_check_and_callback(:getProxyHistory))
  end
  alias proxy_history getProxyHistory
  alias get_proxy_history getProxyHistory


  # Returns a Java array of IHttpRequestResponse objects pulled directly from 
  # the Burp site map for all urls matching the specified literal prefix. 
  # The prefix can be nil to return all objects.
  # @todo Bring IHttpRequestResponse helper up to date
  def getSiteMap(urlprefix=nil)
    HttpRequestResponseList.new(_check_and_callback(:getSiteMap, urlprefix))
  end
  alias site_map getSiteMap
  alias get_site_map getSiteMap


  # This method returns all of the current scan issues for URLs matching the 
  # specified literal prefix. The prefix can be nil to match all issues.
  #
  # IMPORTANT: This method is only available with Burp 1.2.15 and higher.
  def getScanIssues(urlprefix=nil)
    ScanIssuesList.new( _check_and_callback(:getScanIssues, urlprefix) )
  end
  alias scan_issues getScanIssues
  alias get_scan_issues getScanIssues


  # Restores Burp session state from a previously saved state file.
  # See also: saveState
  #
  # IMPORTANT: This method is only available with Burp 1.2.09 and higher.
  #
  # * filename = path and filename of the file to restore from
  def restoreState(filename)
    _check_and_callback(:restoreState, java.io.File.new(filename))
  end
  alias restore_state restoreState


  # Saves the current Burp session to a state file. See also restoreState.
  #
  # IMPORTANT: This method is only available with Burp 1.2.09 and higher.
  #
  # * filename = path and filename of the file to save to
  def saveState(filename)
    _check_and_callback(:saveState, java.io.File.new(filename))
  end
  alias save_state saveState


  # Parses a raw HTTP request message and returns an associative array 
  # containing parameters as they are structured in the 'Parameters' tab in the 
  # Burp request UI.
  #
  # IMPORTANT: This method is only available with Burp 1.2.09+ and deprecated in 1.5.01
  #
  # This method parses the specified request and returns details of each
  # request parameter.
  #
  # @param request The request to be parsed.
  # @return An array of:
  #   <code>String[] { name, value, type }</code> containing details of the
  #   parameters contained within the request.
  # @deprecated Use +IExtensionHelpers.analyzeRequest()+ instead.
  #
  def getParameters(request)
    request = request.to_java_bytes if request.is_a? String
    _check_and_callback(:getParameters, request)
  end
  alias parameters getParameters
  alias get_parameters getParameters


  # Parses a raw HTTP message (request or response ) and returns an associative
  # array containing the headers as they are structured in the 'Headers' tab 
  # in the Burp request/response viewer UI.
  #
  # IMPORTANT: This method is only available with Burp 1.2.09+ and is deprecated in 1.5.01
  #
  # This method parses the specified request and returns details of each HTTP
  # header.
  #
  # @param message The request to be parsed.
  # @return An array of HTTP headers.
  # @deprecated Use
  # <code>IExtensionHelpers.analyzeRequest()</code> or
  # <code>IExtensionHelpers.analyzeResponse()</code> instead.
  #
  def getHeaders(message)
    message = message.to_java_bytes if message.is_a? String
    _check_and_callback(:getHeaders, message)
  end
  alias headers getHeaders
  alias get_headers getHeaders

  # Shuts down Burp programatically. If the method returns the user cancelled
  # the shutdown prompt.
  def exitSuite(prompt_user=false)
    _check_and_callback(:exitSuite, prompt_user ? true : false)
  end
  alias exit_suite exitSuite
  alias close exitSuite

  # This method can be used to register a new menu item which will appear on
  # the various context menus that are used throughout Burp Suite to handle
  # user-driven actions.
  #
  # @param menuItemCaption The caption to be displayed on the menu item.
  # @param menuItemHandler The handler to be invoked when the user clicks on
  # the menu item.
  # @deprecated Use {#registerContextMenuFactory} instead.
  #
  # This method is only available with Burp 1.3.07+ and is deprecated in 1.5.01.
  #
  def registerMenuItem(menuItemCaption, menuItemHandler)
    _check_and_callback(:registerMenuItem, menuItemCaption, menuItemHandler)
    issueAlert("Handler #{menuItemHandler} registered for \"#{menuItemCaption}\"")
  end
  alias register_menu_item registerMenuItem

  ### 1.3.09 methods ###

  # This method can be used to add an item to Burp's site map with the
  # specified request/response details. This will overwrite the details
  # of any existing matching item in the site map.
  # 
  # @param item Details of the item to be added to the site map
  #
  # This method is only available with Burp 1.3.09+
  def addToSiteMap(item)
    _check_and_callback(:addToSiteMap, item)
  end
  alias add_to_site_map addToSiteMap

  # This method causes Burp to save all of its current configuration as a
  # Map of name/value Strings.
  #
  # @return A Map of name/value Strings reflecting Burp's current
  # configuration.
  #
  # This method is only available with Burp 1.3.09+
  def saveConfig
    _check_and_callback(:saveConfig).to_hash
  end
  alias save_config saveConfig
  alias config saveConfig

  # This method causes Burp to load a new configuration from the Map of
  # name/value Strings provided. Any settings not specified in the Map will
  # be restored to their default values. To selectively update only some
  # settings and leave the rest unchanged, you should first call
  # <code>saveConfig</code> to obtain Burp's current configuration, modify
  # the relevant items in the Map, and then call <code>loadConfig</code>
  # with the same Map.
  #
  # @param config A map of name/value Strings to use as Burp's new
  # configuration.
  #
  # This method is only available with Burp 1.3.09+
  def loadConfig(config)
    _check_and_callback(:loadConfig, config)
  end
  alias load_config loadConfig
  alias config= loadConfig

  ## 1.4 methods ##

  # This method sets the interception mode for Burp Proxy.
  # 
  # @param enabled Indicates whether interception of proxy messages should 
  # be enabled.
  # 
  def setProxyInterceptionEnabled(enabled)
    _check_and_callback(:setProxyInterceptionEnabled, enabled)
  end
  alias proxy_interception_enabled setProxyInterceptionEnabled
  alias proxy_interception= setProxyInterceptionEnabled

  # This method can be used to determine the version of the loaded burp at runtime.
  # This is included in the Javadoc for the extension interfaces but not the supplied interface files.
  # @return String array containing the product name, major version, and minor version.
  def getBurpVersion
    begin
      _check_and_callback(:getBurpVersion)
    rescue
      nil
    end
  end
  alias burp_version getBurpVersion
  alias get_burp_version getBurpVersion

  # This method is used to set the display name for the current extension,
  # which will be displayed within the user interface for the Extender tool.
  #
  # @param [String] name The extension name.
  # @return [void]
  #
  def setExtensionName(name)
    _check_and_callback(:setExtensionName, name)
  end
  alias extension_name= setExtensionName
  alias set_extension_name setExtensionName

  # This method is used to obtain an
  # <code>IExtensionHelpers</code> object, which can be used by the extension
  # to perform numerous useful tasks.
  #
  # @return An object containing numerous helper methods, for tasks such as
  # building and analyzing HTTP requests.
  #
  def getHelpers
    Buby::Implants::ExtensionHelpers.implant(_check_and_callback(:getHelpers))
  end
  alias helpers getHelpers
  alias get_helpers getHelpers

  # This method is used to obtain the current extension's standard output
  # stream. Extensions should write all output to this stream, allowing the
  # Burp user to configure how that output is handled from within the UI.
  #
  # @return [OutputStream] The extension's standard output stream.
  #
  # @todo double check
  def getStdout
    _check_and_callback(:getStdout)
  end
  alias stdout getStdout
  alias get_stdout getStdout

  # This method is used to obtain the current extension's standard error
  # stream. Extensions should write all error messages to this stream,
  # allowing the Burp user to configure how that output is handled from
  # within the UI.
  #
  # @return [OutputStream] The extension's standard error stream.
  #
  def getStderr
    _check_and_callback(:getStderr)
  end
  alias stderr getStderr
  alias get_stderr getStderr

  # This method is used to register a listener which will be notified of
  # changes to the extension's state. <b>Note:</b> Any extensions that start
  # background threads or open system resources (such as files or database
  # connections) should register a listener and terminate threads / close
  # resources when the extension is unloaded.
  #
  # @overload registerExtensionStateListener(listener)
  #   @param [IExtensionStateListener] listener A listener for extension
  #    state events
  # @overload registerExtensionStateListener(&block)
  #   @param [Proc] &block A listener for extension state events
  #    (Isn't JRuby fun?)
  #
  def registerExtensionStateListener(listener = nil, &block)
    _check_and_callback(:registerExtensionStateListener, listener || block)
  end
  alias register_extension_state_listener registerExtensionStateListener

  # This method is used to register a listener which will be notified of
  # requests and responses made by any Burp tool. Extensions can perform
  # custom analysis or modification of these messages by registering an HTTP
  # listener.
  #
  # @overload registerHttpListener(listener)
  #   @param [IHttpListener] listener A listener for http events
  # @overload registerHttpListener(&block)
  #   @param [Proc] &block A listener for http events
  #    (Isn't JRuby fun?)
  #
  def registerHttpListener(listener = nil, &block)
    _check_and_callback(:registerHttpListener, listener || block)
  end
  alias register_http_listener registerHttpListener

  # This method is used to register a listener which will be notified of
  # requests and responses being processed by the Proxy tool. Extensions can
  # perform custom analysis or modification of these messages, and control
  # in-UI message interception, by registering a proxy listener.
  #
  # @overload registerProxyListener(listener)
  #   @param [IProxyListener] listener A listener for proxy events
  # @overload registerHttpListener(&block)
  #   @param [Proc] &block A listener for proxy events
  #    (Isn't JRuby fun?)
  #
  def registerProxyListener(listener = nil, &block)
    _check_and_callback(:registerProxyListener, listener || block)
  end
  alias register_proxy_listener registerProxyListener

  # This method is used to register a listener which will be notified of new
  # issues that are reported by the Scanner tool. Extensions can perform
  # custom analysis or logging of Scanner issues by registering a Scanner
  # listener.
  #
  # @overload registerScannerListener(listener)
  #   @param [IScannerListener] listener A listener for scanner events
  # @overload registerScannerListener(&block)
  #   @param [Proc] &block A listener for scanner events
  #    (Isn't JRuby fun?)
  #
  def registerScannerListener(listener = nil, &block)
    _check_and_callback(:registerScannerListener, listener || block)
  end
  alias register_scanner_listener registerScannerListener

  # This method is used to register a listener which will be notified of
  # changes to Burp's suite-wide target scope.
  #
  # @overload registerScopeChangeListener(listener)
  #   @param [IScopeChangeListener] listener A listener for scope change events
  # @overload registerScopeChangeListener(&block)
  #   @param [Proc] &block A listener for scope change events
  #    (Isn't JRuby fun?)
  #
  def registerScopeChangeListener(listener = nil, &block)
    _check_and_callback(:registerScopeChangeListener, listener || block)
  end

  # This method is used to register a factory for custom context menu items.
  # When the user invokes a context menu anywhere within Burp, the factory
  # will be passed details of the invocation event, and asked to provide any
  # custom context menu items that should be shown.
  #
  # @overload registerContextMenuFactory(factory)
  #   @param [IContextMenuFactory] factory A listener for context
  #     menu invocation events
  # @overload registerContextMenuFactory(&block)
  #   @param [Proc] &block A listener for context menu invocation events
  #     (Isn't JRuby fun?)
  #   @note It is probably better to use the more explicit +factory+ argument
  #     version to ensure the +IContextMenuInvocation+ Java classes have been
  #     wrapped properly.
  #
  def registerContextMenuFactory(factory = nil, &block)
    _check_and_callback(:registerContextMenuFactory, factory || block)
  end
  alias register_context_menu_factory registerContextMenuFactory

  # This method is used to register a factory for custom message editor tabs.
  # For each message editor that already exists, or is subsequently created,
  # within Burp, the factory will be asked to provide a new instance of an
  # <code>IMessageEditorTab</code> object, which can provide custom rendering
  # or editing of HTTP messages.
  #
  # @overload registerMessageEditorTabFactory(factory)
  #   @param [IMessageEditorTabFactory] factory A listener for message editor
  #     tab events
  # @overload registerMessageEditorTabFactory(&block)
  #   @param [Proc] &block A listener for message editor tab events
  #     (Isn't JRuby fun?)
  #   @note It is probably better to use the more explicit +factory+ argument
  #     version to ensure the +IMessageEditorController+ Java classes have been
  #     wrapped properly.
  #
  def registerMessageEditorTabFactory(factory = nil, &block)
    _check_and_callback(:registerMessageEditorTabFactory, factory || block)
  end
  alias register_message_editor_tab_factory registerMessageEditorTabFactory

  # This method is used to register a provider of Scanner insertion points.
  # For each base request that is actively scanned, Burp will ask the
  # provider to provide any custom scanner insertion points that are
  # appropriate for the request.
  #
  # @overload registerScannerInsertionPointProvider(provider)
  #   @param [IScannerInsertionPointProvider] provider A provider of scanner
  #     insertion points
  # @overload registerScannerInsertionPointProvider(&block)
  #   @param [Proc] &block A provider of scanner insertion points
  #     (Isn't JRuby fun?)
  #
  def registerScannerInsertionPointProvider(provider = nil, &block)
    _check_and_callback(:registerScannerInsertionPointProvider, provider || block)
  end
  alias register_scanner_insertion_point_provider registerScannerInsertionPointProvider

  # This method is used to register a custom Scanner check. When performing
  # scanning, Burp will ask the check to perform active or passive scanning
  # on the base request, and report any Scanner issues that are identified.
  #
  # @param [IScannerCheck] check An object that performs a given check.
  #
  def registerScannerCheck(check)
    _check_and_callback(:registerScannerCheck, check)
  end
  alias register_scanner_check registerScannerCheck

  # This method is used to register a factory for Intruder payloads. Each
  # registered factory will be available within the Intruder UI for the user
  # to select as the payload source for an attack. When this is selected, the
  # factory will be asked to provide a new instance of an
  # +IIntruderPayloadGenerator+ object, which will be used to generate payloads
  # for the attack.
  #
  # @param [IIntruderPayloadGeneratorFactory] factory An object to be used for
  #   generating intruder payloads.
  #
  # @todo Test - block version may work here
  def registerIntruderPayloadGeneratorFactory(factory)
    _check_and_callback(:registerIntruderPayloadGeneratorFactory, factory)
  end
  alias register_intruder_payload_generator_factory registerIntruderPayloadGeneratorFactory

  # This method is used to register a custom Intruder payload processor. Each
  # registered processor will be available within the Intruder UI for the
  # user to select as the action for a payload processing rule.
  #
  # @param [IIntruderPayloadProcessor] processor An object used for processing
  #   Intruder payloads
  #
  # @todo Test - block version may work here
  def registerIntruderPayloadProcessor(processor)
    _check_and_callback(:registerIntruderPayloadProcessor, processor)
  end
  alias register_intruder_payload_processor registerIntruderPayloadProcessor

  # This method is used to register a custom session handling action. Each
  # registered action will be available within the session handling rule UI
  # for the user to select as a rule action. Users can choose to invoke an
  # action directly in its own right, or following execution of a macro.
  #
  # @param [ISessionHandlingAction] action An object used to perform a given session action.
  #
  # @todo Test - block version may work here
  def registerSessionHandlingAction(action)
    _check_and_callback(:registerSessionHandlingAction, action)
  end
  alias register_session_handling_action registerSessionHandlingAction

  # This method is used to add a custom tab to the main Burp Suite window.
  #
  # @param [ITab] tab A tab to be added to the suite's user interface.
  #
  def addSuiteTab(tab)
    _check_and_callback(:addSuiteTab, tab)
  end
  alias add_suite_tab addSuiteTab

  # This method is used to remove a previously-added tab from the main Burp
  # Suite window.
  #
  # @param [ITab] tab The tab to be removed from the suite's user interface.
  #
  def removeSuiteTab(tab)
    _check_and_callback(:removeSuiteTab, tab)
  end
  alias remove_suite_tab removeSuiteTab

  # This method is used to customize UI components in line with Burp's UI
  # style, including font size, colors, table line spacing, etc.
  #
  # @param [Component] component The UI component to be customized.
  #
  def customizeUiComponent(component)
    _check_and_callback(:customizeUiComponent, component)
  end
  alias customize_ui_component customizeUiComponent

  # This method is used to create a new instance of Burp's HTTP message
  # editor, for the extension to use in its own UI.
  #
  # @param controller An object created by the extension that implements the
  #   +IMessageEditorController+ interface. This parameter is optional and
  #   defaults to +nil+. If it is provided, then the message editor will query
  #   the controller when required to obtain details about the currently
  #   displayed message, including the +IHttpService+ for the message, and the
  #   associated request or response message. If a controller is not provided,
  #   then the message editor will not support context menu actions, such as
  #   sending requests to other Burp tools.
  # @param [Boolean] editable Indicates whether the editor created should be
  #   editable, or used only for message viewing.
  # @return [IMessageEditor] An object which the extension can use in
  #   its own UI.
  #
  def createMessageEditor(controller = nil, editable = true)
    Buby::Implants::MessageEditor.implant _check_and_callback(:createMessageEditor, controller, editable)
  end
  alias create_message_editor createMessageEditor

  # This method is used to save configuration settings for the extension in a
  # persistent way that survives reloads of the extension and of Burp Suite.
  # Saved settings can be retrieved using the method {#loadExtensionSetting}.
  #
  # @param [String] name The name of the setting.
  # @param [String] value The value of the setting. If this value is +nil+ then
  #   any existing setting with the specified name will be removed.
  #
  def saveExtensionSetting(name, value)
    _check_and_callback(:saveExtensionSetting, name, value)
  end
  alias save_extension_setting saveExtensionSetting

  # This method is used to load configuration settings for the extension that
  # were saved using the method
  # <code>saveExtensionSetting()</code>.
  #
  # @param [String] name The name of the setting.
  # @return [String] The value of the setting, or +nil+ if no value is set.
  #
  def loadExtensionSetting(name)
    _check_and_callback(:loadExtensionSetting, name)
  end
  alias load_extension_setting loadExtensionSetting

  # This method is used to create a new instance of Burp's plain text editor,
  # for the extension to use in its own UI.
  #
  # @return [ITextEditor] A new text editor the extension can use in its own UI.
  #
  def createTextEditor()
    _check_and_callback(:createTextEditor)
  end
  alias create_text_editor createTextEditor

  # This method is used to retrieve the contents of Burp's session handling
  # cookie jar. Extensions that provide an +ISessionHandlingAction+ can query
  # and update the cookie jar in order to handle unusual session handling
  # mechanisms.
  #
  # @return [Array<ICookie>] An array of the cookies representing the contents
  #   of Burp's session handling cookie jar.
  #
  def getCookieJarContents
    _check_and_callback(:getCookieJarContents).tap{|arr| Buby::Implants::Cookie.implant(arr.first)}
  end
  alias get_cookie_jar_contents getCookieJarContents
  alias cookie_jar_contents getCookieJarContents

  # This method is used to update the contents of Burp's session handling
  # cookie jar. Extensions that provide an
  # <code>ISessionHandlingAction</code> can query and update the cookie jar
  # in order to handle unusual session handling mechanisms.
  #
  # @param [ICookie] cookie An object containing details of the cookie to be
  #   updated. If the cookie jar already contains a cookie that matches the
  #   specified domain and name, then that cookie will be updated with the new
  #   value and expiration, unless the new value is +nil+, in which case the
  #   cookie will be removed. If the cookie jar does not already contain a
  #   cookie that matches the specified domain and name, then the cookie will
  #   be added.
  #
  # @see Buby::Cookie
  def updateCookieJar(cookie)
    _check_and_callback(:updateCookieJar, cookie)
  end
  alias update_cookie_jar updateCookieJar

  # This method is used to create a temporary file on disk containing the
  # provided data. Extensions can use temporary files for long-term storage
  # of runtime data, avoiding the need to retain that data in memory.
  # Not strictly needed in JRuby (use Tempfile class in stdlib instead) but might see use.
  #
  # @param [String, Array<byte>] buffer The data to be saved to a temporary file.
  # @return [ITempFile] A reference to the temp file.
  #
  def saveToTempFile(buffer)
    buffer = buffer.to_java_bytes if buffer.respond_to? :to_java_bytes
    _check_and_callback(:saveToTempFile, buffer)
  end
  alias save_to_temp_file saveToTempFile

  # This method is used to save the request and response of an
  # +IHttpRequestResponse+ object to temporary files, so that they are no longer
  # held in memory. Extensions can used this method to convert
  # +IHttpRequestResponse+ objects into a form suitable for long-term storage.
  #
  # @param [IHttpRequestResponse] httpRequestResponse The request and response
  #   messages to be saved to temporary files.
  # @return [IHttpRequestResponsePersisted] A reference to the saved temp file.
  #
  # @todo move HttpRequestResponse to new Implants method...
  def saveBuffersToTempFiles(httpRequestResponse)
    _check_and_callback(:saveBuffersToTempFiles, httpRequestResponse).tap{|obj| Buby::HttpRequestResponseHelper.implant(obj)}
  end
  alias save_buffers_to_temp_files saveBuffersToTempFiles

  # This method is used to apply markers to an HTTP request or response, at
  # offsets into the message that are relevant for some particular purpose.
  # Markers are used in various situations, such as specifying Intruder
  # payload positions, Scanner insertion points, and highlights in Scanner
  # issues.
  #
  # @param [IHttpRequestResponse] httpRequestResponse The object to which the
  #   markers should be applied.
  # @param [Array<Array<Fixnum>>] requestMarkers A list of index pairs
  #   representing the offsets of markers to be applied to the request message.
  #   Each item in the list must be an +int[2]+ array containing the start and
  #   end offsets for the marker. This parameter is optional and may be +nil+ if
  #   no request markers are required.
  # @param [Array<Array<Fixnum>>] responseMarkers A list of index pairs
  #   representing the offsets of markers to be applied to the response message.
  #   Each item in the list must be an +int[2]+ array containing the start and
  #   end offsets for the marker. This parameter is optional and may be +nil+ if
  #   no response markers are required.
  # @return [IHttpRequestResponseWithMarkers] A marked request/response pair.
  #
  # @todo Bring IHttpRequestResponse helper up to date
  def applyMarkers(httpRequestResponse, requestMarkers, responseMarkers)
    _check_and_callback(:applyMarkers, httpRequestResponse, requestMarkers, responseMarkers).tap{|obj| Buby::HttpRequestResponseHelper.implant(obj)}
  end
  alias apply_markers applyMarkers

  # This method is used to obtain the descriptive name for the Burp tool
  # identified by the tool flag provided.
  #
  # @param [Fixnum] toolFlag A flag identifying a Burp tool (+TOOL_PROXY+, +TOOL_SCANNER+, etc.). Tool flags are defined within this interface.
  # @return [String] The descriptive name for the specified tool.
  #
  def getToolName(toolFlag)
    _check_and_callback(:getToolName, toolFlag)
  end
  alias get_tool_name getToolName

  # This method is used to register a new Scanner issue.
  # @note Wherever possible, extensions should implement custom Scanner checks
  #   using +IScannerCheck+ and report issues via those checks, so as to
  #   integrate with Burp's user-driven workflow, and ensure proper
  #   consolidation of duplicate reported issues. This method is only designed
  #   for tasks outside of the normal testing workflow, such as importing
  #   results from other scanning tools.
  #
  # @param [IScanIssue] issue An issue to be added to the scan results.
  #
  def addScanIssue(issue)
    _check_and_callback(:addScanIssue, issue)
  end
  alias add_scan_issue addScanIssue

  ### Event Handlers ###
  # @todo move event handler base logic to java side

  # This method is called by the BurpExtender java implementation upon 
  # initialization of the BurpExtender instance for Burp. The args parameter
  # is passed with a instance of the newly initialized BurpExtender instance 
  # so that implementations can access and extend its public interfaces.
  #
  # The return value is ignored.
  def evt_extender_init ext
    @burp_extender = ext
    pp([:got_extender, ext]) if $DEBUG
  end

  # This method is called by the BurpExtender implementation Burp startup.
  # The args parameter contains main()'s argv command-line arguments array. 
  #
  # Note: This maps to the 'setCommandLineArgs' method in the java 
  # implementation of BurpExtender.
  #
  # The return value is ignored.
  # @deprecated - nothing calls this anymore
  def evt_command_line_args args
    pp([:got_args, args]) if $DEBUG
  end

  # This method is called by BurpExtender on startup to register Burp's 
  # IBurpExtenderCallbacks interface object.
  #
  # This maps to the 'registerExtenderCallbacks' method in the Java 
  # implementation of BurpExtender.
  #
  # The return value is ignored.
  def evt_register_callbacks cb
    @burp_callbacks = cb
    cb.issueAlert("[JRuby::#{self.class}] registered callback")
    pp([:got_callbacks, cb]) if $DEBUG
  end

  ACTION_FOLLOW_RULES              = Java::Burp::IInterceptedProxyMessage::ACTION_FOLLOW_RULES
  ACTION_DO_INTERCEPT              = Java::Burp::IInterceptedProxyMessage::ACTION_DO_INTERCEPT
  ACTION_DONT_INTERCEPT            = Java::Burp::IInterceptedProxyMessage::ACTION_DONT_INTERCEPT
  ACTION_DROP                      = Java::Burp::IInterceptedProxyMessage::ACTION_DROP
  ACTION_FOLLOW_RULES_AND_REHOOK   = Java::Burp::IInterceptedProxyMessage::ACTION_FOLLOW_RULES_AND_REHOOK
  ACTION_DO_INTERCEPT_AND_REHOOK   = Java::Burp::IInterceptedProxyMessage::ACTION_DO_INTERCEPT_AND_REHOOK
  ACTION_DONT_INTERCEPT_AND_REHOOK = Java::Burp::IInterceptedProxyMessage::ACTION_DONT_INTERCEPT_AND_REHOOK
  # Flag used to identify Burp Suite as a whole.
  TOOL_SUITE                       = Java::Burp::IBurpExtenderCallbacks::TOOL_SUITE
  # Flag used to identify the Burp Target tool.
  TOOL_TARGET                      = Java::Burp::IBurpExtenderCallbacks::TOOL_TARGET
  # Flag used to identify the Burp Proxy tool.
  TOOL_PROXY                       = Java::Burp::IBurpExtenderCallbacks::TOOL_PROXY
  # Flag used to identify the Burp Spider tool.
  TOOL_SPIDER                      = Java::Burp::IBurpExtenderCallbacks::TOOL_SPIDER
  # Flag used to identify the Burp Scanner tool.
  TOOL_SCANNER                     = Java::Burp::IBurpExtenderCallbacks::TOOL_SCANNER
  # Flag used to identify the Burp Intruder tool.
  TOOL_INTRUDER                    = Java::Burp::IBurpExtenderCallbacks::TOOL_INTRUDER
  # Flag used to identify the Burp Repeater tool.
  TOOL_REPEATER                    = Java::Burp::IBurpExtenderCallbacks::TOOL_REPEATER
  # Flag used to identify the Burp Sequencer tool.
  TOOL_SEQUENCER                   = Java::Burp::IBurpExtenderCallbacks::TOOL_SEQUENCER
  # Flag used to identify the Burp Decoder tool.
  TOOL_DECODER                     = Java::Burp::IBurpExtenderCallbacks::TOOL_DECODER
  # Flag used to identify the Burp Comparer tool.
  TOOL_COMPARER                    = Java::Burp::IBurpExtenderCallbacks::TOOL_COMPARER
  # Flag used to identify the Burp Extender tool.
  TOOL_EXTENDER                    = Java::Burp::IBurpExtenderCallbacks::TOOL_EXTENDER

  # Seems we need to specifically render our 'message' to a string here in
  # ruby. Otherwise there's flakiness when converting certain binary non-ascii
  # sequences. As long as we do it here, it should be fine.
  #
  # Note: This method maps to the 'processProxyMessage' method in the java 
  # implementation of BurpExtender.
  #
  # This method just handles the conversion to and from evt_proxy_message
  # which expects a message string 
  def evt_proxy_message_raw msg_ref, is_req, rhost, rport, is_https, http_meth, url, resourceType, status, req_content_type, message, action
    pp [:evt_proxy_message_raw_hit, msg_ref, is_req, rhost, rport, is_https, http_meth, url, resourceType, status, req_content_type, message, action ] if $DEBUG

    str_msg = String.from_java_bytes(message)
    ret = evt_proxy_message(msg_ref, is_req, rhost, rport, is_https, http_meth, url, resourceType, status, req_content_type, str_msg, action)

    message = ret.to_java_bytes if ret.object_id != str_msg.object_id
    return message
  end

  # This method is called by BurpExtender while proxying HTTP messages and
  # before passing them through the Burp proxy. Implementations can use this
  # method to implement arbitrary processing upon HTTP requests and responses 
  # such as interception, logging, modification, and so on.
  #
  # The 'is_req' parameter indicates whether it is a response or request.
  #
  # Note: This method maps to the 'processProxyMessage' method in the java 
  # implementation of BurpExtender.
  # 
  # See also, evt_proxy_message_raw which is actually called before this
  # in the BurpExtender processProxyMessage handler.
  #
  # Below are the parameters descriptions based on the IBurpExtender 
  # javadoc. Where applicable, decriptions have been modified for 
  # local parameter naming and other ruby-specific details added.
  #
  # * msg_ref:
  #   An identifier which is unique to a single request/response pair. This 
  #   can be used to correlate details of requests and responses and perform 
  #   processing on the response message accordingly. This number also 
  #   corresponds to the Burp UI's proxy "history" # column.
  #
  # * is_req: (true/false)
  #   Flags whether the message is a client request or a server response.
  #
  # * rhost:
  #   The hostname of the remote HTTP server.
  #
  # * rport:
  #   The port of the remote HTTP server.
  #
  # * is_https:
  #   Flags whether the protocol is HTTPS or HTTP.
  #
  # * http_meth:
  #   The method verb used in the client request.
  #
  # * url:
  #   The requested URL. Set in both the request and response.
  #
  # * resourceType:
  #   The filetype of the requested resource, or nil if the resource has no 
  #   filetype.
  #
  # * status:
  #   The HTTP status code returned by the server. This value is nil for 
  #   request messages.
  #
  # * req_content_type:
  #   The content-type string returned by the server. This value is nil for 
  #   request messages.
  #
  # * message:
  #   The full HTTP message.  
  #   **Ruby note: 
  #     For convenience, the message is received and returned as a ruby 
  #     String object. Internally within Burp it is handled as a java byte[] 
  #     array. See also the notes about the return object below.
  #
  # * action:
  #   An array containing a single integer, allowing the implementation to 
  #   communicate back to Burp Proxy a non-default interception action for 
  #   the message. The default value is ACTION_FOLLOW_RULES (or 0). 
  #   Possible values include:
  #     ACTION_FOLLOW_RULES = 0
  #     ACTION_DO_INTERCEPT = 1
  #     ACTION_DONT_INTERCEPT = 2
  #     ACTION_DROP = 3
  #
  #   Refer to the BurpExtender.java source comments for more details.
  #
  #
  # Return Value:
  #   Implementations should return either (a) the same object received
  #   in the message paramater, or (b) a different object containing a 
  #   modified message. 
  #
  # **IMPORTANT RUBY NOTE:
  # Always be sure to return a new object if making modifications to messages.
  #
  # Explanation: 
  # The (a) and (b) convention above is followed rather literally during type 
  # conversion on the return value back into the java BurpExtender.
  #
  # When determining whether a change has been made in the message or not, 
  # the decision is made based on whether the object returned is the same
  # as the object submitted in the call to evt_proxy_message. 
  #
  #
  # So, for example, using in-place modification of the message using range 
  # substring assignments or destructive method variations like String.sub!() 
  # and String.gsub! alone won't work because the same object gets returned 
  # to BurpExtender. 
  #
  # In short, this means that if you want modifications to be made, be sure
  # to return a different String than the one you got in your handler.
  #
  # So for example this code won't do anything at all:
  #
  #   ...
  #   message.sub!(/^GET /, "HEAD ")
  #   return message
  #
  # Nor this:
  #
  #   message[0..4] = "HEAD "
  #   return message
  #
  # But this will
  #
  #   ...
  #   return message.sub(/^GET /, "HEAD ")
  #
  # And so will this
  #
  #   ...
  #   message[0..4] = "HEAD "
  #   return message.dup
  #
  # @deprecated Legacy - Use {Buby#process_proxy_message} or
  #   {Buby::ProxyListener}
  def evt_proxy_message msg_ref, is_req, rhost, rport, is_https, http_meth, url, resourceType, status, req_content_type, message, action
    pp([ (is_req)? :got_proxy_request : :got_proxy_response,
         [:msg_ref, msg_ref], 
         [:is_req, is_req], 
         [:rhost, rhost], 
         [:rport, rport], 
         [:is_https, is_https], 
         [:http_meth, http_meth], 
         [:url, url], 
         [:resourceType, resourceType], 
         [:status, status], 
         [:req_content_type, req_content_type], 
         [:message, message], 
         [:action, action[0]] ]) if $DEBUG
    
    return message
  end

  # This method is invoked when an HTTP message is being processed by the Proxy.
  #
  # @param [Boolean] messageIsRequest Indicates whether the HTTP message is a
  #   request or a response.
  # @param [IInterceptedProxyMessage] message An +IInterceptedProxyMessage+
  #   object that extensions can use to query and update details of the
  #   message, and control whether the message should be intercepted and
  #   displayed to the user for manual review or modification.
  # @return [void]
  #
  # @see Buby::ProxyListener
  def process_proxy_message(messageIsRequest, message)
    pp [:got_processProxyMessage] if $debug
    Buby::Implants::InterceptedProxyMessage.implant message
  end

  # This method is invoked whenever any of Burp's tools makes an HTTP request 
  # or receives a response. This is effectively a generalised version of the 
  # pre-existing evt_proxy_message method, and can be used to intercept and 
  # modify the HTTP traffic of all Burp tools.
  #
  # IMPORTANT: This event handler is only used in Burp version 1.2.09 and 
  # higher.
  # 
  # Note: this method maps to the processHttpMessage BurpExtender Java method.
  #
  # This method should be overridden if you wish to implement functionality
  # relating to generalized requests and responses from any BurpSuite tool.
  #
  # You may want to use evt_proxy_message if you only intend to work on
  # proxied messages. Note, however, the IHttpRequestResponse Java object is 
  # not used in evt_proxy_message and gives evt_http_message a somewhat 
  # nicer interface to work with.
  #
  # Parameters:
  # * tool_name = a string name of the tool that generated the message
  #
  # * is_request = boolean true = request / false = response
  #
  # * message_info = an instance of the IHttpRequestResponse Java class with
  #   methods for accessing and manipulating various attributes of the message.
  #
  # @todo Bring IHttpRequestResponse helper up to date
  # @note Changed in Burp 1.5.01+
  # @deprecated This is the called by the legacy interface, use
  #   {#process_http_method} instead
  def evt_http_message(tool_name, is_request, message_info)
    HttpRequestResponseHelper.implant(message_info)
    pp([:got_evt_http_message, tool_name, is_request, message_info]) if $DEBUG
  end


  # This method is invoked when an HTTP request is about to be issued, and
  # when an HTTP response has been received.
  #
  # @param [Fixnum] toolFlag A flag indicating the Burp tool that issued the
  #   request. Burp tool flags are defined in the +IBurpExtenderCallbacks+
  #   interface.
  # @param [Boolean] messageIsRequest Flags whether the method is being invoked
  #   for a request or response.
  # @param [IHttpRequestResponse] messageInfo Details of the request / response
  #   to be processed. Extensions can call the setter methods on this object to
  #   update the current message and so modify Burp's behavior.
  # @return [void]
  # @note This is the 1.5.01+ version of this callback
  #
  def process_http_message(toolFlag, messageIsRequest, messageInfo)
    HttpRequestResponseHelper.implant(message_info)
    pp([:got_process_http_message, tool_name, is_request, message_info]) if $DEBUG
  end

  # This method is invoked whenever Burp Scanner discovers a new, unique 
  # issue, and can be used to perform customised reporting or logging of 
  # detected issues.
  #
  # IMPORTANT: This event handler is only used in Burp version 1.2.09 and 
  # higher.
  #
  # Note: this method maps to the BurpExtender Java method.
  #
  # Parameters:
  # * issue = an instance of the IScanIssue Java class with methods for viewing
  #   information on the scan issue that was generated.
  def evt_scan_issue(issue)
    ScanIssueHelper.implant(issue)
    pp([:got_scan_issue, issue]) if $DEBUG
  end

  # This method is called by BurpExtender right before closing the
  # application. Implementations can use this method to perform cleanup
  # tasks such as closing files or databases before exit.
  def evt_application_closing 
    pp([:got_app_close]) if $DEBUG
  end

  # This method is called by BurpExtender right before unloading the
  # extension. Implementations can use this method to perform cleanup
  # tasks such as closing files or databases before exit.
  def evt_extension_unloaded 
    pp([:got_ext_unload]) if $DEBUG
  end

  ### Sugar/Convenience methods

  # This is a convenience wrapper which can load a given burp state file and 
  # lets its caller to perform actions inside of a block on the site map 
  # contained in the loaded session. 
  #
  # If a statefile argument isn't specified current burp session state is used.
  #
  # Yields each entry in the site map to a block.
  def with_site_map(urlprefix=nil, statefile=nil)
    with_statefile(statefile) do |this|
      this.site_map(urlprefix).each {|h| yield h }
    end
  end

  # This is a convenience wrapper which can load a given burp state file and 
  # lets its caller to perform actions inside of a block on the proxy history 
  # contained in the loaded session. 
  #
  # If a statefile argument isn't specified current burp session state is used.
  #
  # Yields each entry in the proxy history to a block.
  def with_proxy_history(statefile=nil)
    with_statefile(statefile) do |this|
      this.proxy_history.each {|h| yield h }
    end
  end

  # This is a convenience wrapper which loads a given burp statefile and lets
  # its caller perform actions via burp while its loaded on it inside of a 
  # block. The old state is restored after the block completes.
  #
  # It can safely be run with a nil statefile argument in which the 
  # current burp session state is used.
  def with_statefile(statefile=nil)
    if statefile
      # save current state:
      old_state=".#{$$}.#{Time.now.to_i}.state.bak"
      self.alert "Saving current state to temp statefile: #{old_state}"
      self.save_state(old_state)
      self.alert "Restoring state: #{statefile}"
      self.restore_state(statefile)
    end

    yield self

    if statefile
      # restore original state
      self.alert "Restoring temp statefile: #{old_state}"
      self.restore_state old_state
      self.alert "Deleting temp state file: #{old_state}"
      File.unlink old_state
    end
  end

  # Searches the proxy history for the url's matched by the specified 
  # regular expression (returns them all if urlrx is nil).
  #
  # A statefile to search in can optionally be specified or the existing
  # state will be used if statefile is nil.
  #
  # This method also accepts an optional block which is passed each of the
  # matched history members.
  def search_proxy_history(statefile=nil, urlrx=nil)
    ret = []
    with_proxy_history(statefile) do |r|
      if (not urlrx) or r.url.to_s =~ urlrx
        ret << r if (not block_given?) or yield(r)
      end
    end
    return ret
  end

  # Harvest cookies from a session's proxy history.
  #
  # Params:
  #   cookie    = optional: name of cookie to harvest
  #   urlrx     = optional: regular expression to match urls against
  #   statefile = optional: filename for a burp session file to temporarily load
  #               and harvest from.
  #
  # Takes an optional block as additional 'select' criteria for cookies.
  # The block return value of true/false will determine whether a cookie 
  # string is selected.
  def harvest_cookies_from_history(cookie=nil, urlrx=nil, statefile=nil)
    ret = []
    search_proxy_history(statefile, urlrx) do |hrr|
      if heads=hrr.rsp_headers
        ret += heads.select do |h| 
          h[0].downcase == 'set-cookie' and (not block_given? or yield(h[1]))
        end.map{|h| h[1]}
      end
    end
    return ret
  end

  ### Startup stuff

  # Prepares the java BurpExtender implementation with a reference
  # to self as the module handler and launches burp suite.
  def start_burp(args=[])
    activate!()
    Java::Burp::StartBurp.main(args.to_java(:string))
    return self
  end

  # Starts burp using a supplied handler class, 
  #  h_class = Buby or a derived class. instance of which will become handler.
  #  args = arguments to Burp
  #  init_args = arguments to the handler constructor
  #
  #  Returns the handler instance
  def self.start_burp(h_class=nil, init_args=nil, args=nil)
    h_class ||= self
    init_args ||= []
    args ||= []
    h_class.new(*init_args).start_burp(args)
  end

  # Attempts to load burp with require and confirm it provides the required 
  # class in the Java namespace.
  #
  # Returns: true/false depending on whether the required jar provides us
  # the required class
  #
  # Raises: may raise the usual require exceptions if jar_path is bad.
  def self.load_burp(jar_path)
    require jar_path
    return burp_loaded?
  end

  # Checks the Java namespace to see if Burp has been loaded.
  def self.burp_loaded?
    @burp_loaded ||= begin
      java_import 'burp.StartBurp'
      true
    rescue NameError
      false
    end
  end

  ### Extra cruft added by Mr Bones:

  # Returns the library path for the module. If any arguments are given,
  # they will be joined to the end of the libray path using
  # <tt>File.join</tt>.
  #
  def self.libpath( *args )
    args.empty? ? LIBPATH : ::File.join(LIBPATH, args.flatten)
  end

  # Returns the lpath for the module. If any arguments are given,
  # they will be joined to the end of the path using
  # <tt>File.join</tt>.
  #
  def self.path( *args )
    args.empty? ? PATH : ::File.join(PATH, args.flatten)
  end

  # Utility method used to require all files ending in .rb that lie in the
  # directory below this file that has the same name as the filename passed
  # in. Optionally, a specific _directory_ name can be passed in such that
  # the _filename_ does not have to be equivalent to the directory.
  #
  def self.require_all_libs_relative_to( fname, dir = nil )
    dir ||= ::File.basename(fname, '.*')
    search_me = ::File.expand_path(
        ::File.join(::File.dirname(fname), dir, '**', '*.rb'))

    Dir.glob(search_me).sort.each {|rb| require rb}
  end

end # Buby


# Try requiring 'burp.jar' from the Ruby lib-path
unless Buby.burp_loaded?
  begin require "burp.jar" 
  rescue LoadError 
  end
end


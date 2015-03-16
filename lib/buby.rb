require 'pp'
require 'uri'
require 'buby/implants'

# load the Burp extender interfaces if they're not already accessible
begin
  Java::Burp::IBurpExtender
rescue NameError
  require 'burp_interfaces.jar'
end

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
# == CREDIT:
# Burp and Burp Suite are trademarks of PortSwigger(ltd)
#   Copyright 2013 PortSwigger Ltd. All rights reserved.
#   See http://portswigger.net for license terms.
#
# This JRuby library and the accompanying Java and JRuby BurpExtender
# implementations were written by Timur Duehr @ Matasano Security. The original
# version of this library and BurpExtender.java implementation was written by
# Eric Monti @ Matasano Security. Matasano Security claims no professional or
# legal affiliation with PortSwigger LTD.
#
# However, the authors would like to express their personal and professional
# respect and admiration to Burp's authors and appreciation to PortSwigger for
# the availability of the IBurpExtender extension API and its continued
# improvement. The availability of this interface goes a long way to helping
# make Burp Suite a truly first-class application.
#
# @todo move more to BurpExtender side
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
  autoload :ProxyListener, 'buby/proxy_listener'
  autoload :ScanIssue, 'buby/scan_issue'
  autoload :ScannerCheck, 'buby/scanner_check'
  autoload :ScannerInsertionPoint, 'buby/scanner_insertion_point'
  autoload :ScannerInsertionPointProvider, 'buby/scanner_insertion_point_provider'
  autoload :ScannerListener, 'buby/scanner_listener'
  autoload :ScopeChangeListener, 'buby/scope_change_listener'
  autoload :SessionHandlingAction, 'buby/session_handling_action'
  autoload :Tab, 'buby/tab'
  autoload :Version, 'buby/version'

  # @deprecated moving to proper version module
  VERSION = Buby::Version::STRING

  # latest tested version of burp
  COMPAT_VERSION = '1.5.17'

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
  # @param extender Buby's BurpExtender interface
  def activate!(extender)
    extender.handler = self
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

  # This method can be used to send an HTTP request to the Burp Scanner tool
  # to perform an active vulnerability scan. If the request is not within the
  # current active scanning scope, the user will be asked if they wish to
  # proceed with the scan.
  #
  # @overload doActiveScan(host, port, useHttps, request, insertionPointOffsets = nil)
  #   @param [String, java.net.URL, URI] host The hostname of the remote HTTP
  #     server.
  #   @param [Fixnum] port The port of the remote HTTP server.
  #   @param [Boolean] useHttps Flags whether the protocol is HTTPS or HTTP.
  #   @param [String, Array<byte>, IHttpRequestResponse] request The full HTTP
  #     request.
  #   @param [Array<Array<Fixnum>>] insertionPointOffsets A list of index pairs
  #     representing the positions of the insertion points that should be
  #     scanned. Each item in the list must be an +int\[2]+ array containing the
  #     start and end offsets for the insertion point.
  # @overload doActiveScan(request, insertionPointOffsets = nil)
  #   @param [IHttpRequestResponse] request Request object containing details
  #     about the request to scan.
  #   @param [Array<Array<Fixnum>>] insertionPointOffsets A list of index pairs
  #     representing the positions of the insertion points that should be
  #     scanned. Each item in the list must be an +int\[2]+ array containing the
  #     start and end offsets for the insertion point.
  # @overload doActiveScan(service, request, insertionPointOffsets = nil)
  #   @param [IHttpService] service Object describing host, port and protocol
  #     for scan.
  #   @param [IHttpRequestResponse, String, Array<byte>] request Request object
  #     containing details about the request to scan.
  #   @param [Array<Array<Fixnum>>] insertionPointOffsets A list of index pairs
  #     representing the positions of the insertion points that should be
  #     scanned. Each item in the list must be an +int\[2]+ array containing the
  #     start and end offsets for the insertion point.
  # @overload doActiveScan(url, insertionPointOffsets = nil)
  #   @param [String, URI, java.net.URL] url Build a +GET+ request and scan url.
  #   @param [Array<Array<Fixnum>>] insertionPointOffsets A list of index pairs
  #     representing the positions of the insertion points that should be
  #     scanned. Each item in the list must be an +int\[2]+ array containing the
  #     start and end offsets for the insertion point.
  # @return [IScanQueueItem] The resulting scan queue item.
  #
  def doActiveScan(*args)
    raise ArgumentError, "wrong number of arguments calling '#{__callee__}' (#{args.size} for 1..5)" unless (1..5).include?(args.size)
    host, port, https, req, ip_off = *args
    if args.size < 4
      case args.first
      when Java::Burp::IHttpRequestResponse
        raise ArgumentError, "wrong number/type of arguments calling '#{__callee__}' (#{args.size} for 1..5)" unless args.size < 3
        req, ip_off = *args
        host = req.host
        port = req.port
        https = req.protocol
      when Java::Burp::IHttpService
        raise ArgumentError, "wrong number/type of arguments calling '#{__callee__}' (#{args.size} for 1..5)" unless args.size
        serv, req, ip_off = *args
        https = serv.getProtocol
        host = serv.getHost
        port = serv.getPort
        req = req.request
      else
        url = (req.kind_of?(URI) || req.kind_of?(Java::JavaNet::URL)) ? req : Java::JavaNet::URL.new(req.to_s)
        req = helpers.buildHttpRequest req
        host = url.host
        port = url.port
        https = url.respond_to? :scheme ? url.scheme : url.protocol
      end
    end

    https = case https.to_s.downcase
    when 'https'
      true
    when 'http'
      false
    else
      !!https
    end

    port ||= https ? 443 : 80
    port = https ? 443 : 80 if port < 0
    host = host.host if host.respond_to? :host

    req = req.request if req.respond_to? :request
    req = req.to_java_bytes if req.respond_to? :to_java_bytes
    scanq = if getBurpVersion
      _check_and_callback :doActiveScan, host, port, https, req, ip_off
    else
      _check_and_callback :doActiveScan, host, port, https, req
    end
    Buby::Implants::ScanQueueItem.implant scanq
  end
  alias do_active_scan doActiveScan
  alias active_scan doActiveScan

  # Send an HTTP request and response to the Burp Scanner tool to perform a
  # passive vulnerability scan.
  # @overload doPassiveScan(host, port, useHttps, request, response)
  #   @param [String, java.net.URL, URI] host The hostname of the remote HTTP
  #     server.
  #   @param [Fixnum] port The port of the remote HTTP server.
  #   @param [Boolean] useHttps Flags whether the protocol is HTTPS or HTTP.
  #   @param [String, Array<byte>, IHttpRequestResponse] request The full HTTP request.
  #   @param [String, Array<byte>, IHttpRequestResponse] response The full HTTP response.
  # @overload doPassiveScan(host, port, useHttps, request_response)
  #   @param [String, java.net.URL, URI] host The hostname of the remote HTTP
  #     server.
  #   @param [Fixnum] port The port of the remote HTTP server.
  #   @param [Boolean] useHttps Flags whether the protocol is HTTPS or HTTP.
  #   @param [String, Array<byte>, IHttpRequestResponse] request The full HTTP request and response.
  # @overload doPassiveScan(service, request, response)
  #   @param [IHttpService] service Object describing host, port and protocol
  #     for scan.
  #   @param [IHttpRequestResponse, String, Array<byte>] request Request object
  #     containing details about the request to scan.
  #   @param [IHttpRequestResponse, String, Array<byte>] request Request object
  #     containing details about the response to scan.
  # @overload doPassiveScan(service, request_response)
  #   @param [IHttpService] service Object describing host, port and protocol
  #     for scan.
  #   @param [IHttpRequestResponse, String, Array<byte>] request Request object
  #     containing details about the request to scan.
  # @return [IScanQueueItem] The resulting scan queue item.
  # @overload doPassiveScan(request)
  #   @param [IHttpRequestResponse] request Request object containing details
  #     about the request to scan.
  #
  def doPassiveScan(*args)
    raise ArgumentError, "wrong number of arguments calling '#{__callee__}' (#{args.size} for 1..4)" unless (1..4).include?(args.size)
    host, port, https, req, resp = *args
    case args.size
    when 1
      req = args.first
      host = req.getHost
      port = req.getPort
      https = req.getProtocol
      resp = req.getResponse
    when 2, 3
      serv, req = *args
      host = serv.getHost
      port = serv.getPort
      https = req.getProtocol
      resp = (resp && resp.getResponse) || req.getResponse
    when 4
      resp = req.response
    else
      # nop
    end

    https = case https.to_s.downcase
    when 'https'
      true
    when 'http'
      false
    else
      !!https
    end

    port ||= https ? 443 : 80
    port = https ? 443 : 80 if port < 0
    host = host.host if host.respond_to? :host

    req = req.request if req.respond_to? :request
    req = req.to_java_bytes if req.respond_to? :to_java_bytes

    resp = resp.response if resp.respond_to? :response
    resp = resp.to_java_bytes if resp.respond_to? :to_java_bytes

    Buby::Implants::ScanQueueItem.implant(_check_and_callback(:doPassiveScan, host, port, https, req, resp))
  end
  alias do_passive_scan doPassiveScan
  alias passive_scan doPassiveScan

  # Exclude the specified URL from the Suite-wide scope.
  # @overload excludeFromScope(url)
  #   @param [java.net.URL, URI, String] url The URL to exclude from the
  #     Suite-wide scope.
  # @overload excludeFromScope(req)
  #   @param [IHttpRequestResponse] req The request to exclude from the
  #     Suite-wide scope.
  # @overload excludeFromScope(req_info)
  #   @param [IRequestInfo] req_info The request information to exclude from
  #     the Suite-wide scope.
  # @overload excludeFromScope(serv, req)
  #   @param [IHttpService] serv The HTTP service to exclude from the Suite-wide
  #     scope.
  #   @param [Array<byte>, String] req The request to exclude
  #
  # @return [void]
  def excludeFromScope(*args)
    url, req = args
    case args.size
    when 1
      case url
      when Java::Burp::IHttpRequestResponse,  Java::Burp::IRequestInfo
        url = url.getUrl
      else
        url = Java::JavaNet::URL.new(url.to_s) unless url.is_a? Java::JavaNet::URL
      end
    when 2
      url = getHelpers.__analyzeRequest(url, req).getUrl
    else
      raise ArgumentError, "wrong number of arguments calling '#{__callee__}' (#{args.size} for 1,2)"
    end
    _check_and_callback :excludeFromScope, url
  end
  alias exclude_from_scope excludeFromScope
  alias exclude_scope excludeFromScope

  # Include the specified URL in the Suite-wide scope.
  # @overload includeInScope(url)
  #   @param [java.net.URL, URI, String] url The URL to include in the
  #     Suite-wide scope.
  # @overload includeInScope(req)
  #   @param [IHttpRequestResponse] req The request to include in the Suite-wide
  #     scope.
  # @overload includeInScope(req_info)
  #   @param [IRequestInfo] req_info The request information to include in
  #     the Suite-wide scope.
  # @overload includeInScope(serv, req)
  #   @param [IHttpService] serv The HTTP service to include in the Suite-wide
  #     scope.
  #   @param [Array<byte>, String] req The request to include
  #
  # @return [void]
  def includeInScope(*args)
    url, req = args
    case args.size
    when 1
      case url
      when Java::Burp::IHttpRequestResponse,  Java::Burp::IRequestInfo
        url = url.getUrl
      else
        url = Java::JavaNet::URL.new(url.to_s) unless url.is_a? Java::JavaNet::URL
      end
    when 2
      url = getHelpers.__analyzeRequest(url, req).getUrl
    else
      raise ArgumentError, "wrong number of arguments calling '#{__callee__}' (#{args.size} for 1,2)"
    end
    _check_and_callback :includeInScope, url
  end
  alias include_in_scope includeInScope
  alias include_scope includeInScope

  # Query whether a specified URL is within the current Suite-wide scope.
  # @overload isInScope(url)
  #   @param [java.net.URL, URI, String] url The URL to query
  # @overload isInScope(req)
  #   @param [IHttpRequestResponse] req The request to query
  # @overload isInScope(req_info)
  #   @param [IRequestInfo] req_info The request info to query
  # @overload isInScope(serv, req)
  #   @param [IHttpService] serv The HTTP service to query
  #   @param [Array<byte>, String] req The request to query
  #
  # @return [Boolean]
  def isInScope(*args)
    url, req = args
    case args.size
    when 1
      case url
      when Java::Burp::IHttpRequestResponse,  Java::Burp::IRequestInfo
        url = url.getUrl
      else
        url = Java::JavaNet::URL.new(url.to_s) unless url.is_a? Java::JavaNet::URL
      end
    when 2
      url = getHelpers.__analyzeRequest(url, req).getUrl
    else
      raise ArgumentError, "wrong number of arguments calling '#{__callee__}' (#{args.size} for 1,2)"
    end
    _check_and_callback :isInScope, url
  end
  alias is_in_scope isInScope
  alias in_scope? isInScope

  # Display a message in the Burp Suite alerts tab.
  # @param [#to_s] msg The alert message to display.
  # @return [void]
  def issueAlert(msg)
    _check_and_callback :issueAlert, msg.to_s
  end
  alias issue_alert issueAlert
  alias alert issueAlert

  # Issue an arbitrary HTTP request and retrieve its response
  # @overload makeHttpRequest(host, port, https, request)
  #   @param [String, java.net.URL, URI] host The hostname of the remote HTTP
  #     server.
  #   @param [Fixnum] port The port of the remote HTTP server.
  #   @param [Boolean] useHttps Flags whether the protocol is HTTPS or HTTP.
  #   @param [String, Array<byte>, IHttpRequestResponse] request The full HTTP
  #     request.
  # @overload makeHttpRequest(request)
  #   @param [IHttpRequestResponse] request The full HTTP request
  # @overload makeHttpRequest(url)
  #   @param [String, URI, java.net.URL] url The url to make a GET request to.
  #     The request is built with {ExtensionHelpers#buildHttpRequest}
  # @overload makeHttpRequest(service, request)
  #   @param [IHttpService] service Object with host, port, etc.
  #   @param [String, Array<byte>, IHttpRequestResponse] request The full HTTP
  #     request.
  # @return [IHttpRequestResponse] The full response retrieved from the remote server.
  #
  def makeHttpRequest(*args)
    raise ArgumentError, "wrong number of arguments calling '#{__callee__}' (#{args.size} for 1,2,4)" unless [1,2,4].include?(args.size)
    host, port, https, req, serv = args

    case args.size
    when 1
      case host
      when Java::Burp::IHttpRequestResponse
        req = host
        serv = req.getHttpService
      else
        host = Java::JavaNet::URL.new host.to_s unless host.kind_of?(Java::JavaNet::URL)
        port = host.port
        https = host.protocol
        req = getHelpers.__buildHttpRequest host
        https = case https.to_s.downcase
        when 'https'
          true
        when 'http'
          false
        else
          !!https
        end

        port ||= https ? 443 : 80
        port = https ? 443 : 80 if port < 0

        host = host.host if host.respond_to? :host
        serv = getHelpers.buildHttpService(host, port, https)
      end
    when 2
      serv, req = args
    when 4
      # nop
    else
      raise ArgumentError
    end

    req = req.request if req.respond_to? :request
    req = req.to_java_bytes if req.respond_to? :to_java_bytes

    ret = if serv
      _check_and_callback(:makeHttpRequest, serv, req)
    else
      String.from_java_bytes _check_and_callback(:makeHttpRequest, host, port, https, req)
    end
  end
  alias make_http_request makeHttpRequest
  alias make_request makeHttpRequest

  # Send an HTTP request to the Burp Intruder tool
  #
  # @overload sendToIntruder(host, port, https, req, ip_off=nil)
  #   @param [String] host The hostname of the remote HTTP server.
  #   @param [Fixnum] port The port of the remote HTTP server.
  #   @param [Boolean, #to_s] https Flags whether the protocol is HTTPS or HTTP.
  #   @param [String, Array<byte>, IHttpRequestResponse] req The full HTTP
  #     request.
  #   @param [Array<Array<Fixnum>>] ip_off A list of index pairs representing
  #     the positions of the insertion points that should be scanned. Each item
  #     in the list must be an +int[2]+ array containing the start and end
  #     offsets for the insertion point.
  # @overload sendToIntruder(request, ip_off=nil)
  #   @param [IHttpRequestResponse] request The complete request to send to
  #     Intruder.
  #   @param [Array<Array<Fixnum>>] ip_off A list of index pairs representing
  #     the positions of the insertion points that should be scanned. Each item
  #     in the list must be an +int[2]+ array containing the start and end
  #     offsets for the insertion point.
  # @overload sendToIntruder(service, request, ip_off=nil)
  #   @param [IHttpService] service The HTTP service description for the request
  #   @param [IHttpRequestResponse, String, Array<byte>] request The complete
  #     request to send to Intruder. If +String+ or +Array<byte>+ the request
  #     will first be analyzed with #analyzeRequest to obtain the required
  #     information
  #   @param [Array<Array<Fixnum>>] ip_off A list of index pairs representing
  #     the positions of the insertion points that should be scanned. Each item
  #     in the list must be an +int[2]+ array containing the start and end
  #     offsets for the insertion point.
  #
  # @return [void]
  def sendToIntruder(*args)
    host, port, https, req, ip_off = nil
    case args.first
    when String
      raise ArgumentError, "wrong number/type of arguments calling '#{__callee__}' (#{args.size} for 1..5)" unless [4,5].include?(args.size)
      host, port, https, req, ip_off = *args
    when Java::Burp::IHttpRequestResponse
      raise ArgumentError, "wrong number/type of arguments calling '#{__callee__}' (#{args.size} for 1..5)" unless [1,2].include?(args.size)
      req, ip_off = *args
      port  = req.port
      https = req.protocol
      host  = req.host
    when Java::Burp::IHttpService
      raise ArgumentError, "wrong number/type of arguments calling '#{__callee__}' (#{args.size} for 1..5)" unless [2,3].include?(args.size)
      serv, req, ip_off = *args
      port  = serv.port
      https = serv.protocol
      host  = serv.host
    else
      raise ArgumentError, "wrong number/type of arguments calling '#{__callee__}' (#{args.size} for 1..5)"
    end

    https = case https.to_s.downcase
    when 'https'
      true
    when 'http'
      false
    else
      !!https
    end

    req = req.request if req.respond_to?(:request)
    req = req.to_java_bytes if req.respond_to?(:to_java_bytes)
    if self.getBurpVersion.to_a[1..-1].join(".") < "1.4.04"
      _check_and_callback :sendToIntruder, host, port, https, req
    else
      _check_and_callback :sendToIntruder, host, port, https, req, ip_off
    end
  end
  alias send_to_intruder sendToIntruder
  alias intruder sendToIntruder

  # This method can be used to send data to the Comparer tool.
  #
  # @overload sendToComparer(data)
  #   @param [Array<Byte>, String] data The data to be sent to Comparer.
  # @overload sendToComparer(data, use_req=nil)
  #   @param [IHttpRequestResponse] data Request/Response to be sent to Comparer.
  #   @param [Boolean] use_req Use request instead of response
  #
  def sendToComparer(data, use_req=nil)
    if data.kind_of? Java::Burp::IHttpRequestResponse
      data = use_req ? data.request : data.response
    end
    data = data.to_java_bytes if data.respond_to? :to_java_bytes
    _check_and_callback(:sendToComparer, data)
  end
  alias send_to_comparer sendToComparer
  alias comparer sendToComparer

  # Send an HTTP request to the Burp Repeater tool.
  #
  # @overload sendToRepeater(host, port, https, req, tab=nil)
  #   @param [String] host The hostname of the remote HTTP server.
  #   @param [Fixnum] port The port of the remote HTTP server.
  #   @param [Boolean, #to_s] https Flags whether the protocol is HTTPS or HTTP.
  #   @param [String, Array<byte>, IHttpRequestResponse] req The full HTTP
  #     request. (String or Java +byte[]+)
  #   @param [String] tab The tab caption displayed in Repeater. (default:
  #     auto-generated)
  # @overload sendToRepeater(service, request, tab=nil)
  #   @param [IHttpService] service The HTTP service description for the request
  #   @param [IHttpRequestResponse, String, Array<byte>] request The complete
  #     request to send to Intruder. If +String+ or +Array<byte>+ the request
  #     will first be analyzed with #analyzeRequest to obtain the required
  #     information
  #   @param [String] tab The tab caption displayed in Repeater. (default:
  #     auto-generated)
  # @overload sendToRepeater(request, tab=nil)
  #   @param [IHttpRequestResponse] request The request to be sent to Repeater
  #     containing all the required information.
  #   @param [String] tab The tab caption displayed in Repeater. (default:
  #     auto-generated)
  # @return [void]
  def sendToRepeater(*args)
    host, port, https, req, tab = nil
    case args.first
    when String
      raise ArgumentError, "wrong number/type of arguments calling '#{__callee__}' (#{args.size} for 1..5)" unless [4,5].include?(args.size)
      host, port, https, req, tab = *args
    when Java::Burp::IHttpRequestResponse
      raise ArgumentError, "wrong number/type of arguments calling '#{__callee__}' (#{args.size} for 1..5)" unless [1,2].include?(args.size)
      req, tab = *args
      port  = req.port
      https = req.protocol
      host  = req.host
    when Java::Burp::IHttpService
      raise ArgumentError, "wrong number/type of arguments calling '#{__callee__}' (#{args.size} for 1..5)" unless [2,3].include?(args.size)
      serv, req, tab = *args
      port  = serv.port
      https = serv.protocol
      host  = serv.host
    else
      raise ArgumentError, "wrong number/type of arguments calling '#{__callee__}' (#{args.size} for 1..5)"
    end

    https = case https.to_s.downcase
    when 'https'
      true
    when 'http'
      false
    else
      !!https
    end

    req = req.request if req.kind_of?(Java::Burp::IHttpRequestResponse)
    req = req.to_java_bytes if req.respond_to?(:to_java_bytes)
    _check_and_callback :sendToRepeater, host, port, https, req, tab
  end
  alias send_to_repeater sendToRepeater
  alias repeater sendToRepeater

  # Send a seed URL to the Burp Spider tool.
  #  @param [String, URI, java.net.URL, IHttpRequestResponse] url The new seed URL to begin
  #    spidering from.
  #  @return [void]
  def sendToSpider(url)
    url = url.url if url.respond_to? :url
    url = Java::JavaNet::URL.new(url.to_s) unless url.kind_of?(Java::JavaNet::URL)
    _check_and_callback :sendToSpider, url
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
    begin
      _check_cb.__send__ meth, *args, &block
    rescue NoMethodError
      raise "#{meth} is not available in your version of Burp"
    end
  end


  # Returns a Java array of IHttpRequestResponse objects pulled directly from
  # the Burp proxy history.
  # @todo Bring IHttpRequestResponse helper up to date
  # @return [HttpRequestResponseList]
  def getProxyHistory
    HttpRequestResponseList.new(_check_and_callback(:getProxyHistory))
  end
  alias proxy_history getProxyHistory
  alias get_proxy_history getProxyHistory


  # Returns a Java array of IHttpRequestResponse objects pulled directly from
  # the Burp site map for all urls matching the specified literal prefix.
  # The prefix can be nil to return all objects.
  # @todo Bring IHttpRequestResponse helper up to date
  # @param [String, java.net.URL, URI, nil] urlprefix
  # @return [HttpRequestResponseList]
  def getSiteMap(urlprefix=nil)
    HttpRequestResponseList.new(_check_and_callback(:getSiteMap, urlprefix && urlprefix.to_s))
  end
  alias site_map getSiteMap
  alias get_site_map getSiteMap


  # This method returns all of the current scan issues for URLs matching the
  # specified literal prefix. The prefix can be nil to match all issues.
  #
  # @param [String, java.net.URL, URI, nil] urlprefix
  # @return [ScanIssuesList]
  def getScanIssues(urlprefix=nil)
    ScanIssuesList.new( _check_and_callback(:getScanIssues, urlprefix && urlprefix.to_s) )
  end
  alias scan_issues getScanIssues
  alias get_scan_issues getScanIssues


  # Restores Burp session state from a previously saved state file.
  # See also: saveState
  #
  # IMPORTANT: This method is only available with Burp 1.2.09 and higher.
  #
  # @param [String, java.io.File] filename path and filename of the file to
  #   restore from
  # @return [void]
  def restoreState(filename)
    _check_and_callback(:restoreState, Java::JavaIo::File.new(filename))
  end
  alias restore_state restoreState


  # Saves the current Burp session to a state file. See also restoreState.
  #
  # IMPORTANT: This method is only available with Burp 1.2.09 and higher.
  #
  # @param [String, java.io.File] filename path and filename of the file to
  #   save to
  # @return [void]
  def saveState(filename)
    _check_and_callback(:saveState, Java::JavaIo::File.new(filename))
  end
  alias save_state saveState


  # Parses a raw HTTP request message and returns an associative array
  # containing parameters as they are structured in the 'Parameters' tab in the
  # Burp request UI.
  #
  # This method parses the specified request and returns details of each
  # request parameter.
  #
  # @note This method is only available with Burp 1.2.09+ and is deprecated in 1.5.01+
  # @param [Array<btye>, String] request The request to be parsed.
  # @return [Array<Array<String{ name, value, type }>>] details of the
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
  # This method parses the specified request and returns details of each HTTP
  # header.
  #
  # @note This method is only available with Burp 1.2.09+ and is deprecated in 1.5.01+
  # @param [Array<byte>, String] message The request to be parsed.
  # @return [Array<Array<String>>] An array of HTTP headers.
  # @deprecated Use +IExtensionHelpers.analyzeRequest+ or
  #   +IExtensionHelpers.analyzeResponse()+ instead.
  #
  def getHeaders(message)
    message = message.to_java_bytes if message.is_a? String
    _check_and_callback(:getHeaders, message)
  end
  alias headers getHeaders
  alias get_headers getHeaders

  # Shuts down Burp programatically. If the method returns the user cancelled
  # the shutdown prompt.
  # @param [Boolean] prompt_user Display a dialog to confirm shutdown
  # @return [void]
  def exitSuite(prompt_user=false)
    _check_and_callback(:exitSuite, prompt_user)
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
  # @note This method is only available with Burp 1.3.07+ and is deprecated in 1.5.01.
  #
  def registerMenuItem(menuItemCaption, menuItemHandler = nil, &block)
    ret = if block_given?
      _check_and_callback(:registerMenuItem, menuItemCaption, &block)
    else
      _check_and_callback(:registerMenuItem, menuItemCaption, menuItemHandler)
    end
    issueAlert("Handler #{menuItemHandler} registered for \"#{menuItemCaption}\"")
    ret
  end
  alias register_menu_item registerMenuItem

  ### 1.3.09 methods ###

  # This method can be used to add an item to Burp's site map with the
  # specified request/response details. This will overwrite the details
  # of any existing matching item in the site map.
  #
  # @param [IHttpRequestResponse] item Details of the item to be added to the
  #   site map
  #
  # This method is only available with Burp 1.3.09+
  def addToSiteMap(item)
    _check_and_callback(:addToSiteMap, item)
  end
  alias add_to_site_map addToSiteMap

  # This method causes Burp to save all of its current configuration as a
  # Map of name/value Strings.
  #
  # @return [java.util.Map] A Map of name/value Strings reflecting Burp's
  #   current configuration.
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
  # +saveConfig+ to obtain Burp's current configuration, modify the relevant
  # items in the Map, and then call +loadConfig+ with the same Map.
  #
  # @param [Hash, java.util.Map] config A map of name/value Strings to use as
  #   Burp's new configuration.
  # @return [void]
  #
  # This method is only available with Burp 1.3.09+
  # @todo updateConfig
  def loadConfig(config)
    _check_and_callback(:loadConfig, config)
  end
  alias load_config loadConfig
  alias config= loadConfig

  ## 1.4 methods ##

  # This method sets the interception mode for Burp Proxy.
  #
  # @param [Boolean] enabled Indicates whether interception of proxy messages
  #   should be enabled.
  # @return [void]
  #
  def setProxyInterceptionEnabled(enabled)
    _check_and_callback(:setProxyInterceptionEnabled, enabled)
  end
  alias proxy_interception_enabled setProxyInterceptionEnabled
  alias proxy_interception= setProxyInterceptionEnabled

  # This method can be used to determine the version of the loaded burp at runtime.
  # @return [Array<String>] the product name, major version, and minor version.
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
    @helpers ||= Buby::Implants::ExtensionHelpers.implant(_check_and_callback(:getHelpers))
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
    @stdout ||= _check_and_callback(:getStdout)
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
    @stderr ||= _check_and_callback(:getStderr)
  end
  alias stderr getStderr
  alias get_stderr getStderr


  # This method prints a line of output to the current extension's standard
  # output stream.
  #
  # @param output The message to print.
  # @return [void]
  #
  def printOutput(output)
    _check_and_callback(:printOutput, output)
  end
  alias print_output printOutput

  # This method prints a line of output to the current extension's standard
  # error stream.
  #
  # @param error The message to print.
  # @return [void]
  #
  def printError(error)
    _check_and_callback(:printError, error)
  end
  alias print_error printError

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
    if block_given?
      _check_and_callback(:registerExtensionStateListener, &block)
    else
      _check_and_callback(:registerExtensionStateListener, listener)
    end
  end
  alias register_extension_state_listener registerExtensionStateListener


  # This method is used to retrieve the extension state listeners that are
  # registered by the extension.
  #
  # @return [Array<IExtensionStateListener>] A list of extension state listeners
  #   that are currently registered by this extension.
  #
  def getExtensionStateListeners
    _check_and_callback(:getExtensionStateListeners)
  end
  alias get_extension_state_listeners getExtensionStateListeners
  alias extension_state_listeners getExtensionStateListeners


  # This method is used to remove an extension state listener that has been
  # registered by the extension.
  #
  # @param listener The extension state listener to be removed.
  # @return [void]
  #
  def removeExtensionStateListener(listener)
    _check_and_callback(:removeExtensionStateListener, listener)
  end
  alias remove_extension_state_listener removeExtensionStateListener

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
    if block_given?
      _check_and_callback(:registerHttpListener, &block)
    else
      _check_and_callback(:registerHttpListener, listener)
    end
  end
  alias register_http_listener registerHttpListener

  # This method is used to retrieve the HTTP listeners that are registered by
  # the extension.
  #
  # @return [Array<IHttpListener>] A list of HTTP listeners that are currently
  #   registered by this extension.
  #
  def getHttpListeners
    _check_and_callback(:getHttpListeners)
  end
  alias get_http_listeners getHttpListeners
  alias http_listeners getHttpListeners

  # This method is used to remove an HTTP listener that has been registered
  # by the extension.
  #
  # @param listener The HTTP listener to be removed.
  # @return [void]
  #
  def removeHttpListener(listener)
    _check_and_callback(:removeHttpListener, listener)
  end
  alias remove_http_listener removeHttpListener

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
    if block_given?
      _check_and_callback(:registerProxyListener, &block)
    else
      _check_and_callback(:registerProxyListener, listener)
    end
  end
  alias register_proxy_listener registerProxyListener

  # This method is used to retrieve the Proxy listeners that are registered
  # by the extension.
  #
  # @return [Array<IProxyListener>] A list of Proxy listeners that are currently
  #   registered by this extension.
  #
  def getProxyListeners
    _check_and_callback(:getProxyListeners)
  end
  alias get_proxy_listeners getProxyListeners
  alias proxy_listeners getProxyListeners

  # This method is used to remove a Proxy listener that has been registered
  # by the extension.
  #
  # @param [IProxyListener] listener The Proxy listener to be removed.
  # @return [void]
  #
  def removeProxyListener(listener)
    _check_and_callback(:removeProxyListener, listener)
  end
  alias remove_proxy_listener removeProxyListener

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
    if block_given?
      _check_and_callback(:registerScannerListener, &block)
    else
      _check_and_callback(:registerScannerListener, listener)
    end
  end
  alias register_scanner_listener registerScannerListener

  # This method is used to retrieve the Scanner listeners that are registered
  # by the extension.
  #
  # @return [Array<IScannerListener>] A list of Scanner listeners that are
  #   currently registered by this extension.
  #
  def getScannerListeners
    _check_and_callback(:getScannerListeners)
  end
  alias get_scanner_listeners getScannerListeners


  # This method is used to remove a Scanner listener that has been registered
  # by the extension.
  #
  # @param listener The Scanner listener to be removed.
  # @return void
  #
  def removeScannerListener(listener)
    _check_and_callback(:removeScannerListener, listener)
  end
  alias remove_scanner_listener removeScannerListener

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
    if block_given?
      _check_and_callback(:registerScopeChangeListener, &block)
    else
      _check_and_callback(:registerScopeChangeListener, listener)
    end
  end

  # This method is used to retrieve the scope change listeners that are
  # registered by the extension.
  #
  # @return [Array<IScopeChangeListener>] A list of scope change listeners that
  #   are currently registered by this extension.
  #
  def getScopeChangeListeners
    _check_and_callback(:getScopeChangeListeners)
  end
  alias get_scope_change_listeners getScopeChangeListeners
  alias scope_change_listeners getScopeChangeListeners

  # This method is used to remove a scope change listener that has been
  # registered by the extension.
  #
  # @param [IScopeChangeListener] listener The scope change listener to be
  #   removed.
  # @return [void]
  #
  def removeScopeChangeListener(listener)
    _check_and_callback(:removeScopeChangeListener, listener)
  end
  alias remove_scope_change_listener removeScopeChangeListener

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
    if block_given?
      _check_and_callback(:registerContextMenuFactory, &block)
    else
      _check_and_callback(:registerContextMenuFactory, factory)
    end
  end
  alias register_context_menu_factory registerContextMenuFactory

  # This method is used to retrieve the context menu factories that are
  # registered by the extension.
  #
  # @return [Array<IContextMenuFactory>] A list of context menu factories that
  #   are currently registered by this extension.
  #
  def getContextMenuFactories
    _check_and_callback(:getContextMenuFactories)
  end
  alias get_context_menu_factories getContextMenuFactories
  alias context_menu_factories getContextMenuFactories

  # This method is used to remove a context menu factory that has been
  # registered by the extension.
  #
  # @param [IContextMenuFactory] factory The context menu factory to be removed.
  # @return [void]
  #
  def removeContextMenuFactory(factory)
    _check_and_callback(:removeContextMenuFactory, factory)
  end
  alias remove_context_menu_factory removeContextMenuFactory

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
    if block_given?
      _check_and_callback(:registerMessageEditorTabFactory, &block)
    else
      _check_and_callback(:registerMessageEditorTabFactory, factory)
    end
  end
  alias register_message_editor_tab_factory registerMessageEditorTabFactory

  # This method is used to retrieve the message editor tab factories that are
  # registered by the extension.
  #
  # @return [Array<IMessageEditorTabFactory>] A list of message editor tab
  #   factories that are currently registered by this extension.
  #
  def getMessageEditorTabFactories
    _check_and_callback(:getMessageEditorTabFactories)
  end
  alias get_message_editor_tab_factories getMessageEditorTabFactories
  alias message_editor_tab_factories getMessageEditorTabFactories

  # This method is used to remove a message editor tab factory that has been
  # registered by the extension.
  #
  # @param [IMessageEditorTabFactory] factory The message editor tab factory to
  #   be removed.
  # @return [void]
  #
  def removeMessageEditorTabFactory(factory)
    _check_and_callback(:removeMessageEditorTabFactory, factory)
  end
  alias remove_message_editor_tab_factory removeMessageEditorTabFactory

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
    if block_given?
      _check_and_callback(:registerScannerInsertionPointProvider, &block)
    else
      _check_and_callback(:registerScannerInsertionPointProvider, provider)
    end
  end
  alias register_scanner_insertion_point_provider registerScannerInsertionPointProvider

  # This method is used to retrieve the Scanner insertion point providers
  # that are registered by the extension.
  #
  # @return [Array<IScannerInsertionPointProvider>] A list of Scanner insertion
  #   point providers that are currently registered by this extension.
  #
  def getScannerInsertionPointProviders
    _check_and_callback(:getScannerInsertionPointProviders)
  end
  alias get_scanner_insertion_point_providers getScannerInsertionPointProviders
  alias scanner_insertion_point_providers getScannerInsertionPointProviders

  # This method is used to remove a Scanner insertion point provider that has
  # been registered by the extension.
  #
  # @param [IScannerInsertionPointProvider] provider The Scanner insertion point provider to be removed.
  # @return [void]
  #
  def removeScannerInsertionPointProvider(provider)
    _check_and_callback(:removeScannerInsertionPointProvider, provider)
  end
  alias remove_scanner_insertion_point_provider removeScannerInsertionPointProvider

  # This method is used to register a custom Scanner check. When performing
  # scanning, Burp will ask the check to perform active or passive scanning
  # on the base request, and report any Scanner issues that are identified.
  #
  # @param [IScannerCheck] check An object that performs a given check.
  #
  def registerScannerCheck(check = nil, &block)
    if block_given?
      _check_and_callback(:registerScannerCheck, &block)
    else
      _check_and_callback(:registerScannerCheck, check)
    end
  end
  alias register_scanner_check registerScannerCheck

  # This method is used to retrieve the Scanner checks that are registered by
  # the extension.
  #
  # @return [Array<IScannerCheck>] A list of Scanner checks that are currently
  #   registered by this extension.
  #
  def getScannerChecks
    _check_and_callback(:getScannerChecks)
  end
  alias get_scanner_checks getScannerChecks
  alias scanner_checks getScannerChecks

  # This method is used to remove a Scanner check that has been registered by
  # the extension.
  #
  # @param [IScannerCheck] check The Scanner check to be removed.
  # @return [void]
  #
  def removeScannerCheck(check)
    _check_and_callback(:removeScannerCheck, check)
  end
  alias remove_scanner_check removeScannerCheck

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
  def registerIntruderPayloadGeneratorFactory(factory = nil, &block)
    if block_given?
      _check_and_callback(:registerIntruderPayloadGeneratorFactory, &block)
    else
      _check_and_callback(:registerIntruderPayloadGeneratorFactory, factory)
    end
  end
  alias register_intruder_payload_generator_factory registerIntruderPayloadGeneratorFactory

  # This method is used to retrieve the Intruder payload generator factories
  # that are registered by the extension.
  #
  # @return [Array<IIntruderPayloadGeneratorFactory>] A list of Intruder payload
  #   generator factories that are currently registered by this extension.
  #
  def getIntruderPayloadGeneratorFactories
    _check_and_callback(:getIntruderPayloadGeneratorFactories)
  end
  alias get_intruder_payload_generator_factories getIntruderPayloadGeneratorFactories
  alias intruder_payload_generator_factories getIntruderPayloadGeneratorFactories

  # This method is used to remove an Intruder payload generator factory that
  # has been registered by the extension.
  #
  # @param [IIntruderPayloadGeneratorFactory] factory The Intruder payload
  #   generator factory to be removed.
  #
  def removeIntruderPayloadGeneratorFactory(factory)
    _check_and_callback(:removeIntruderPayloadGeneratorFactory, factory)
  end
  alias remove_intruder_payload_generator_factory removeIntruderPayloadGeneratorFactory

  # This method is used to register a custom Intruder payload processor. Each
  # registered processor will be available within the Intruder UI for the
  # user to select as the action for a payload processing rule.
  #
  # @param [IIntruderPayloadProcessor] processor An object used for processing
  #   Intruder payloads
  #
  # @todo Test - block version may work here
  def registerIntruderPayloadProcessor(processor)
    if block_given?
      _check_and_callback(:registerIntruderPayloadProcessor, &block)
    else
      _check_and_callback(:registerIntruderPayloadProcessor, processor)
    end
  end
  alias register_intruder_payload_processor registerIntruderPayloadProcessor

  # This method is used to retrieve the Intruder payload processors that are
  # registered by the extension.
  #
  # @return [Array<IIntruderPayloadProcessor>] A list of Intruder payload
  #   processors that are currently registered by this extension.
  #
  def getIntruderPayloadProcessors
    _check_and_callback(:getIntruderPayloadProcessors)
  end
  alias get_intruder_payload_processors getIntruderPayloadProcessors
  alias intruder_payload_processors getIntruderPayloadProcessors

  # This method is used to remove an Intruder payload processor that has been
  # registered by the extension.
  #
  # @param [IIntruderPayloadProcessor] processor The Intruder payload processor
  #   to be removed.
  # @return [void]
  #
  def removeIntruderPayloadProcessor(processor)
    _check_and_callback(:removeIntruderPayloadProcessor, processor)
  end
  alias remove_intruder_payload_processor removeIntruderPayloadProcessor

  # This method is used to register a custom session handling action. Each
  # registered action will be available within the session handling rule UI
  # for the user to select as a rule action. Users can choose to invoke an
  # action directly in its own right, or following execution of a macro.
  #
  # @param [ISessionHandlingAction] action An object used to perform a given session action.
  #
  # @todo Test - block version may work here
  def registerSessionHandlingAction(action)
    if block_given?
      _check_and_callback(:registerSessionHandlingAction, &block)
    else
      _check_and_callback(:registerSessionHandlingAction, action)
    end
  end
  alias register_session_handling_action registerSessionHandlingAction

  # This method is used to retrieve the session handling actions that are
  # registered by the extension.
  #
  # @return [Array<ISessionHandlingAction>] A list of session handling actions
  #   that are currently registered by this extension.
  #
  def getSessionHandlingActions
    _check_and_callback(:getSessionHandlingActions)
  end
  alias get_session_handling_actions getSessionHandlingActions
  alias session_handling_actions getSessionHandlingActions

  # This method is used to remove a session handling action that has been
  # registered by the extension.
  #
  # @param action The extension session handling action to be removed.
  # @return [void]
  #
  def removeSessionHandlingAction(action)
    _check_and_callback(:removeSessionHandlingAction, action)
  end
  alias remove_session_handling_action removeSessionHandlingAction

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
  def createTextEditor
    Buby::Implants::TextEditor.implant _check_and_callback(:createTextEditor)
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
  # cookie jar. Extensions that provide an +ISessionHandlingAction+ can query
  # and update the cookie jar in order to handle unusual session handling
  # mechanisms.
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
  # Not strictly needed in JRuby (use Tempfile class in stdlib instead) but
  # might see use.
  #
  # @param [String, Array<byte>] buffer The data to be saved to a temporary
  #   file.
  # @return [ITempFile] A reference to the temp file.
  #
  def saveToTempFile(buffer)
    buffer = buffer.to_java_bytes if buffer.respond_to? :to_java_bytes
    Buby::Implants::TempFile.implant(_check_and_callback(:saveToTempFile, buffer))
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
  #   end offsets for the marker. The markers in the list should be in sequence
  #   and not overlapping. This parameter is optional and may be +nil+ if no
  #   response markers are required.
  # @param [Array<Array<Fixnum>>] responseMarkers A list of index pairs
  #   representing the offsets of markers to be applied to the response message.
  #   Each item in the list must be an +int[2]+ array containing the start and
  #   end offsets for the marker. The markers in the list should be in sequence
  #   and not overlapping. This parameter is optional and may be +nil+ if no
  #   response markers are required.
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
  # @param [Fixnum] toolFlag A flag identifying a Burp tool (+TOOL_PROXY+,
  #   +TOOL_SCANNER+, etc.). Tool flags are defined within this interface.
  # @return [String] The descriptive name for the specified tool.
  #
  def getToolName(toolFlag)
    @tool_names[toolFlag] ||= _check_and_callback(:getToolName, toolFlag)
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
  # @todo move basic event handler logic to extender side

  # This method is called by the BurpExtender java implementation upon
  # initialization of the BurpExtender instance for Burp. The args parameter
  # is passed with a instance of the newly initialized BurpExtender instance
  # so that implementations can access and extend its public interfaces.
  #
  # The return value is ignored.
  # @deprecated
  def evt_extender_init ext
    @burp_extender = ext
    pp([:got_extender, ext]) if $DEBUG
  end

  # This method is called by the BurpExtender implementations upon
  # initialization of the BurpExtender instance for Burp. The args parameter
  # is passed with a instance of the newly initialized BurpExtender instance
  # so that implementations can access and extend its public interfaces.
  #
  # @param [IBurpExtender] ext
  # @return [void]
  def extender_initialize ext
    @burp_extender = ext
    @tool_names = {}
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
  # @deprecated
  # @param cb [IBurpExtenderCallbacks] callbacks presented by burp
  # @param alert [Boolean]
  # @return [IBurpExtenderCallbacks] cb
  def evt_register_callbacks cb, alert = true
    cb.issueAlert("[JRuby::#{self.class}] registered callback") if alert
    pp([:got_evt_register_callbacks, cb]) if $DEBUG
    @burp_callbacks = cb
  end

  # This method is called by BurpExtender on startup to register Burp's
  # IBurpExtenderCallbacks interface object.
  #
  # This maps to the 'registerExtenderCallbacks' method in the Java
  # implementation of BurpExtender.
  #
  # @param callbacks [IBurpExtenderCallbacks] callbacks presented by burp
  # @param alert [Boolean]
  # @return [IBurpExtenderCallbacks] cb
  def register_callbacks callbacks, alert = true
    callbacks.issueAlert("[JRuby::#{self.class}] registered callback") if alert
    pp([:got_register_callbacks, callbacks]) if $DEBUG
    evt_register_callbacks(callbacks, false) if respond_to? :evt_register_callbacks
    @burp_callbacks = callbacks
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
  # @deprecated
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
  #   {#process_http_message} instead
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
    HttpRequestResponseHelper.implant(messageInfo)
    pp([:got_process_http_message, toolFlag, messageIsRequest, messageInfo]) if $DEBUG
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
  # @todo move implant to new way...
  # @deprecated
  def evt_scan_issue(issue)
    ScanIssueHelper.implant(issue)
    pp([:got_scan_issue, issue]) if $DEBUG
  end


  # This method is invoked when a new issue is added to Burp Scanner's
  # results.
  #
  # @param [IScanIssue] issue An +IScanIssue+ object that the extension can
  #   query to obtain details about the new issue.
  #
  # @return [void]
  #
  # @abstract
  # @note This maps to the newScanIssue callback in IScannerListener implemented
  #   by the BurpExtender side.
  def new_scan_issue(issue)
    pp [:got_newScanIssue, issue] if $DEBUG
    ScanIssueHelper.implant issue
  end

  # This method is called by BurpExtender right before closing the
  # application. Implementations can use this method to perform cleanup
  # tasks such as closing files or databases before exit.
  # @deprecated
  def evt_application_closing
    pp([:got_app_close]) if $DEBUG
  end

  # This method is called by BurpExtender right before closing the
  # application. Implementations can use this method to perform cleanup
  # tasks such as closing files or databases before exit.
  def application_closing
    pp([:got_app_close]) if $DEBUG
  end

  # This method is called by BurpExtender right before unloading the
  # extension. Implementations can use this method to perform cleanup
  # tasks such as closing files or databases before exit.
  def extension_unloaded
    pp([:got_extension_unloaded]) if $DEBUG
  end

  # This method is used to unload the extension from Burp Suite.
  #
  def unloadExtension
    _check_and_callback(:unloadExtension)
  end
  alias unload_extension unloadExtension

  # This method returns the command line arguments that were passed to Burp
  # on startup.
  #
  # @return [Array<String>] The command line arguments that were passed to Burp on startup.
  #
  def getCommandLineArguments
    _check_and_callback(:getCommandLineArguments)
  end
  alias get_command_line_arguments getCommandLineArguments
  alias command_line_arguments getCommandLineArguments

  # This method is used to generate a report for the specified Scanner
  # issues. The report format can be specified. For all other reporting
  # options, the default settings that appear in the reporting UI wizard are
  # used.
  #
  # @param [String] format The format to be used in the report. Accepted values
  #   are HTML and XML.
  # @param [Array<IScanIssue>] issues The Scanner issues to be reported.
  # @param [String, java.io.File] file The file to which the report will be saved.
  # @return [void]
  #
  def generateScanReport(format, issues, file)
    file = Java::JavaIo::File.new file if file.kind_of?(String)
    _check_and_callback(:generateScanReport, format, issues, file)
  end
  alias generate_scan_report generateScanReport

  # This method retrieves the absolute path name of the file from which the
  # current extension was loaded.
  #
  # @return [String] The absolute path name of the file from which the current
  #   extension was loaded.
  #
  def getExtensionFilename
    _check_and_callback(:getExtensionFilename)
  end
  alias get_extension_filename getExtensionFilename
  alias extension_filename getExtensionFilename

  # This method determines whether the current extension was loaded as a
  # BApp (a Burp App from the BApp Store).
  #
  # @return [boolean] Returns true if the current extension was loaded as a BApp.
  #
  def isExtensionBapp
    _check_and_callback(:isExtensionBapp)
  end
  alias is_extension_bapp isExtensionBapp
  alias extension_bapp? isExtensionBapp
  alias bapp? isExtensionBapp

  ### Sugar/Convenience methods

  # so things will JustWork(tm) for most new interface additions.
  def method_missing(meth, *args, &block)
    if _check_cb.respond_to?(meth)
      warn 'this method may not be implemented fully'
      self.class.class_exec(meth) do |meth|
        define_method(meth) do |*argv, &blck|
          _check_and_callback(meth, *argv, &blck)
        end
      end
      __send__ meth, *args, &block
    else
      super
    end
  end

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
      if (resp = hrr.response)
        ret += helpers.analyzeResponse(resp).getCookies.select do |c|
          (cookie.nil? or c.match(cookie)) && (not block_given? or yield(c))
        end
      end
    end
    return ret
  end

  ### Startup stuff

  # Prepares the java BurpExtender implementation with a reference
  # to self as the module handler and launches burp suite.
  # @param extender Buby exender interface
  def start(extender = nil, args = [])
    # so we don't get error when this file is loaded
    extender ||= legacy_mode? ? Java.burp.BurpExtender : Object.const_get(:BurpExtender)
    activate!(extender)
    Java.burp.StartBurp.main(args.to_java(:string)) if legacy_mode?
    return self
  end

  # @deprecated Use Buby#start instead
  alias start_burp start

  # Starts burp using a supplied handler class
  #
  # @param extender Buby BurpExtender to use for callbacks
  # @param [Class] h_class Buby or a derived class. instance of which will
  #   become handler.
  # @param [Array<String>] args arguments to Burp
  # @param init_args arguments to the handler constructor
  #
  #  @return Buby handler instance
  def self.start(extender = nil, h_class=nil, init_args=nil, args=nil)
    h_class ||= self
    init_args ||= []
    args ||= []
    h_class.new(*init_args).start_burp(extender, args)
  end

  # @see Buby.start
  # @deprecated Use Buby.start instead
  def self.start_burp(extender = nil, h_class = nil, init_args = nil, args = nil)
    self.start(extender, h_class, init_args, args)
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
      Java.burp.StartBurp
      true
    rescue NameError
      false
    end
  end

  # determines if we're running in legacy mode
  # @return [Class, nil]
  def self.legacy_mode?
    @legacy ||= begin
      Java.burp.BurpExtender
    rescue NameError
      false
    end
    @legacy
  end

  def legacy_mode?
    self.class.legacy_mode?
  end

  ### Extra cruft added by Mr Bones:

  # Returns the library path for the module. If any arguments are given,
  # they will be joined to the end of the libray path using
  # <tt>File.join</tt>.
  #
  # @deprecated
  # @api private
  def self.libpath( *args )
    args.empty? ? LIBPATH : ::File.join(LIBPATH, args.flatten)
  end

  # Returns the lpath for the module. If any arguments are given,
  # they will be joined to the end of the path using
  # <tt>File.join</tt>.
  #
  # @deprecated
  # @api private
  def self.path( *args )
    args.empty? ? PATH : ::File.join(PATH, args.flatten)
  end

  # Utility method used to require all files ending in .rb that lie in the
  # directory below this file that has the same name as the filename passed
  # in. Optionally, a specific _directory_ name can be passed in such that
  # the _filename_ does not have to be equivalent to the directory.
  #
  # @deprecated
  # @api private
  def self.require_all_libs_relative_to( fname, dir = nil )
    dir ||= ::File.basename(fname, '.*')
    search_me = ::File.expand_path(
        ::File.join(::File.dirname(fname), dir, '**', '*.rb'))

    Dir.glob(search_me).sort.each {|rb| require rb}
  end

end # Buby

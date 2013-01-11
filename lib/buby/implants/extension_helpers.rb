class Buby
  module Implants
    # This interface contains a number of helper methods, which extensions can
    # use to assist with various common tasks that arise for Burp extensions.
    #
    # Extensions can call +IBurpExtenderCallbacks.getHelpers()+ to obtain an
    # instance of this interface.
    # This module is used to extend the JRuby proxy class returned by Burp.
    #
    module ExtensionHelpers
      include Buby::Implants::Proxy

      # This method can be used to analyze an HTTP request, and obtain various
      # key details about it. The resulting +IRequestInfo+ object
      # will not include the full request URL. To obtain the full URL, use one
      # of the other overloaded {#analyzeRequest} methods.
      #
      # @overload analyzeRequest(request)
      #   Analyze a +HttpRequestResponse+ object.
      #   @param [IHttpRequestResponse] request The request to be analyzed.
      # @overload analyzeRequest(httpService, request)
      #   Analyze a request using +HttpService+, and +String+ or +byte[]+ objects
      #   @param [IHttpService] http_service HTTP service description
      #   @param [String, Array<byte>] request The request to be analyzed
      # @overload analyzeRequest(request)
      #   Analyze a +String+ or +byte[]+ request
      #   @param [String, Array<byte>] request The request to be analyzed
      # @return [IRequestInfo] object (wrapped with Ruby goodness)
      #   that can be queried to obtain details about the request.
      #
      def analyzeRequest(*args)
        pp [:got_analyze_request, *args] if $DEBUG
        args[-1] = args[-1].to_java_bytes if args[-1].kind_of?(String)
        Buby::Implants::RequestInfo.implant(__analyzeRequest(*args))
      end

      # This method can be used to analyze an HTTP response, and obtain various
      # key details about it.
      #
      # @param response The response to be analyzed.
      # @return [IResponseInfo] object (wrapped with Ruby goodness) that can be
      #   queried to obtain details about the response.
      #
      def analyzeResponse(response)
        pp [:got_analyze_response, response] if $DEBUG
        response = String.to_java_bytes if response.kind_of?(String)
        Buby::Implants::ResponseInfo.implant(__analyzeResponse(response))
      end

      # @!method urlDecode(data)
      #   This method can be used to URL-decode the specified data.
      #   @overload urlDecode(data)
      #     URL decode a +String+
      #     @param [String] data The data to be decoded.
      #     @return [String] The decoded data.
      #   @overload urlDecode(data)
      #     URL decode a +byte+ array
      #     @param [byte[]] data The data to be decoded.
      #     @return [byte[]] The decoded data.

      # @!method urlEncode(data)
      #   This method can be used to URL-encode the specified data. Any characters
      #   that do not need to be encoded within HTTP requests are not encoded.
      #   @overload urlEncode(data)
      #     @param [String] data The data to be encoded.
      #     @return [String] The encoded data.
      #   @overload urlEncode(data)
      #     @param [byte[]] data The data to be encoded.
      #     @return [byte[]] The encoded data.
      #

      # This method can be used to retrieve details of a specified parameter
      # within an HTTP request. <b>Note:</b> Use {#analyzeRequest} to obtain
      # details of all parameters within the request.
      #
      # @param [String, byte[]] request The request to be inspected for the specified parameter.
      # @param [String] parameter_name The name of the parameter to retrieve.
      # @return [IParameter] object that can be queried to obtain details
      #   about the parameter, or +nil+ if the parameter was not found.
      #
      def getRequestParameter(request, parameter_name)
        pp [:got_get_request_parameter, parameter_name, request] if $DEBUG
        request = request.to_java_bytes if request.kind_of?(String)
        Buby::Implants::Parameter.implant(__getRequestParameter(request, paramter_name))
      end

      # This method searches a piece of data for the first occurrence of a
      # specified pattern. It works on byte-based data in a way that is similar
      # to the way the native Java method +String.indexOf()+ works on
      # String-based data.
      # @note This method is only wrapped for testing purposes. There are better ways to do this in the JRuby runtime.
      #
      # @param [String, byte[]] data The data to be searched.
      # @param [String, byte[]] pattern The pattern to be searched for.
      # @param [Boolean] case_sensitive Flags whether or not the search is case-sensitive.
      # @param [Fixnum] from The offset within +data+ where the search should begin.
      # @param [Fixnum] to The offset within +data+ where the search should end.
      # @return The offset of the first occurrence of the pattern within the specified bounds, or nil if no match is found.
      #
      def indexOf(data, pattern, case_sensitive, from, to)
        pp [:got_index_of, case_sensitive, from, to, data, pattern] if $DEBUG
        data = data.to_java_bytes if data.respond_to?(:to_java_bytes)
        pattern = pattern.to_java_bytes if data.respond_to?(:to_java_bytes)
        ret = __indexOf(data, pattern, case_sensitive, from, to)
        ret == -1 ? nil : ret
      end

      # This method builds an HTTP message containing the specified headers and
      # message body. If applicable, the Content-Length header will be added or
      # updated, based on the length of the body.
      #
      # @param [Array<String>] headers A list of headers to include in the message.
      # @param [String, Array<byte>] body The body of the message, or +nil+ if the message has an empty body.
      # @return [String] The resulting full HTTP message.
      #
      def buildHttpMessage(headers, body)
        pp [:got_build_http_message, headers, body] if $DEBUG
        body = body.to_java_bytes if body.respond_to?(:to_java_bytes)
        String.from_java_bytes(__buildHttpMessage(headers, body))
      end

      # This method creates a GET request to the specified URL. The headers used
      # in the request are determined by the Request headers settings as
      # configured in Burp Spider's options.
      #
      # @param [URL, #to_s] url The URL to which the request should be made.
      # @return [String] A request to the specified URL.
      #
      def buildHttpRequest(url)
        pp [:got_build_http_request, url] if $DEBUG
        url = Java::JavaNet::URL.new url.to_s unless url.kind_of?(Java::JavaNet::URL)
        String.from_java_bytes __buildHttpRequest(url)
      end

      # This method adds a new parameter to an HTTP request, and if appropriate
      # updates the Content-Length header.
      #
      # @param [String, Array<byte>, IHttpRequestResponse] request The request to which the parameter should be added.
      # @param [IParameter] parameter An +IParameter+ object containing details
      # of the parameter to be added. Supported parameter types are:
      # * +PARAM_URL+,
      # * +PARAM_BODY+
      # * +PARAM_COOKIE+
      # @return [String] A new HTTP request with the new parameter added.
      #
      # @todo Switch IHttpRequestResponse to new Buby::Implants functionality (2.0)
      def addParameter(request, parameter)
        pp [:got_addParameter, parameter, request] if $DEBUG
        request = request.request if request.kind_of? Java::Burp::IHttpRequestResponse
        request = request.to_java_bytes if request.respond_to? :to_java_bytes
        String.from_java_bytes(__addParameter(request, parameter))
      end

      # This method removes a parameter from an HTTP request, and if appropriate
      # updates the Content-Length header.
      #
      # @param [String, Array<byte>, IHttpRequestResponse] request The request
      #   from which the parameter should be removed.
      # @param [IParameter] parameter Object containing details of the parameter
      #   to be removed. Supported parameter types are:
      #   * +PARAM_URL+,
      #   * +PARAM_BODY+
      #   * +PARAM_COOKIE+
      # @return [String] A new HTTP request with the parameter removed.
      #
      # @todo Switch IHttpRequestResponse to new Buby::Implants functionality (2.0)
      def removeParameter(request, parameter);
        pp [:got_addParameter, parameter, request] if $DEBUG
        request = request.request if request.kind_of? Java::Burp::IHttpRequestResponse
        request = request.to_java_bytes if request.respond_to? :to_java_bytes
        String.from_java_bytes(__removeParameter(request, parameter))
      end

      # This method updates the value of a parameter within an HTTP request, and
      # if appropriate updates the Content-Length header.
      # @note: This method can only be used to update the value of an existing
      #   parameter of a specified type. If you need to change the type of an
      #   existing parameter, you should first call {#removeParameter} to remove
      #   the parameter with the old type, and then call {#addParameter} to add
      #   a parameter with the new type.
      #
      # @param [String, Array<byte>, IHttpRequestResponse] request The request
      #   containing the parameter to be updated.
      # @param [IParameter] parameter Object containing details of the parameter
      #   to be updated. Supported parameter types are:
      #   * +PARAM_URL+,
      #   * +PARAM_BODY+
      #   * +PARAM_COOKIE+
      # @return [String] A new HTTP request with the parameter updated.
      #
      # @todo Switch IHttpRequestResponse to new Buby::Implants functionality (2.0)
      def updateParameter(request, parameter)
        pp [:got_updateParameter, parameter, request] if $DEBUG
        request = request.request if request.kind_of? Java::Burp::IHttpRequestResponse
        request = request.to_java_bytes if request.respond_to? :to_java_bytes
        String.from_java_bytes(__updateParameter(request, parameter))
      end

      # This method can be used to toggle a request's method between GET and
      # POST. Parameters are relocated between the URL query string and message
      # body as required, and the Content-Length header is created or removed as
      # applicable.
      #
      # @param [String, Array<byte>, IHttpRequestResponse] request The HTTP
      #  request whose method should be toggled.
      # @return [String} A new HTTP request using the toggled method.
      #
      # @todo Switch IHttpRequestResponse to new Buby::Implants functionality (2.0)
      def toggleRequestMethod(request)
        pp [:got_toggleRequestMethod, request] if $DEBUG
        request = request.request if request.kind_of? Java::Burp::IHttpRequestResponse
        request = request.to_java_bytes if request.respond_to? :to_java_bytes
        String.from_java_bytes(__toggleRequestMethod(request))
      end

      # This method constructs an +IHttpService+ object based on the
      # details provided.
      #
      # @overload buildHttpService(host, port, protocol)
      #   @param [String] host The HTTP service host.
      #   @param [Fixnum] port The HTTP service port.
      #   @param [String] protocol The HTTP service protocol.
      # @overload buildHttpService(host, port, use_https)
      #   @param [String] host The HTTP service host.
      #   @param [Fixnum] port The HTTP service port.
      #   @param [Boolean] use_https Flags whether the HTTP service protocol is HTTPS or HTTP.
      # @return [IHttpService] object based on the details provided.
      #
      def buildHttpService(host, port, protocol)
        pp [:got_buildHttpService, host, port, protocol] if $DEBUG
        Buby::Implants::HttpService.implant(__buildHttpService(host, port, protocol))
      end

      # @!method buildParameter(name, value, type)
      #   This method constructs an
      #   <code>IParameter</code> object based on the details provided.
      #   
      #   @param [String] name The parameter name.
      #   @param [String] value The parameter value.
      #   @param [Fixnum] type The parameter type, as defined in the
      #    +IParameter+ interface.
      #   @return [IParameter] object based on the details provided.

      # This method constructs an +IScannerInsertionPoint+ object based on the
      #  details provided. It can be used to quickly create a simple insertion
      #  point based on a fixed payload location within a base request.
      #
      # @param [String] insertion_point_name The name of the insertion point.
      # @param [String, Array<byte>, IHttpRequestResponse] base_request The request from which to
      #  build scan requests.
      # @param [Fixnum] from The offset of the start of the payload location.
      # @param [Fixnum] to The offset of the end of the payload location.
      # @return [IScannerInsertionPoint] object based on the details provided.
      #
      # @todo Switch IHttpRequestResponse to new Buby::Implants functionality (2.0)
      def makeScannerInsertionPoint(insertion_point_name, base_request, from, to)
        pp [:got_makeScannerInsertionPoint, insertion_point_name, base_request, from, to] if $DEBUG
        base_request = base_request.request if base_request.kind_of? Java::Burp::IHttpRequestResponse
        base_request = base_request.to_java_bytes if base_request.respond_to? :to_java_bytes
        Buby::Implants::ScannerInsertionPoint.implant(__makeScannerInsertionPoint(insertion_point_name, base_request, from, to))
      end
    end

    # Install ourselves into the current +IExtensionHelpers+ java class
    # @param [IExtensionHelpers] helpers
    #
    # @todo __persistent__?
    def self.implant(helpers)
      unless helpers.implanted? || helpers.nil?
        pp [:implanting, helpers, invocation.class] if $DEBUG
        helpers.class.class_exec(self) do
          methods = %w{
            analyzeRequest
            analyzeResponse
            getRequestParameter
            indexOf
            buildHttpMessage
            buildHttpRequest
            addParameter
            removeParameter
            updateParameter
            toggleRequestMethod
            buildHttpService
            makeScannerInsertionPoint            
          }
          methods.each do |meth|
            alias_method "__"+meth, meth
          end
          include Buby::Implants::ExtensionHelpers
          methods.each do |meth|
            rewrap_java_method meth
          end
        end
      end
      helpers
    end
  end
end

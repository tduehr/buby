class Buby
  # This interface is used to define an insertion point for use by active
  # Scanner checks. Extensions can obtain instances of this interface by
  # registering an +IScannerCheck+, or can create instances for use by Burp's
  # own scan checks by registering an +IScannerInsertionPointProvider+.
  #
  # @api
  # @abstract Subclass for specific insertion point flavors used.
  class ScannerInsertionPoint
    include Java::Burb::IScannerInsertionPoint

    INS_PARAM_URL            = 0x00
    INS_PARAM_BODY           = 0x01
    INS_PARAM_COOKIE         = 0x02
    INS_PARAM_XML            = 0x03
    INS_PARAM_XML_ATTR       = 0x04
    INS_PARAM_MULTIPART_ATTR = 0x05
    INS_PARAM_JSON           = 0x06
    INS_PARAM_AMF            = 0x07
    INS_HEADER               = 0x20
    INS_URL_REST             = 0x21
    INS_PARAM_NAME_URL       = 0x22
    INS_PARAM_NAME_BODY      = 0x23
    INS_USER_PROVIDED        = 0x40
    INS_EXTENSION_PROVIDED   = 0x41
    INS_UNKNOWN              = 0x7f

    # @overload initialize(name = nil, type = INS_UNKNOWN, base_value = nil, offsets = nil)
    #   @param [String] name
    #   @param [Fixnum] type
    #   @param [String] base_value
    #   @param [Array<Fixnum>] offsets
    # @overload initialize(hash)
    #   @param [Hash] hash Hash containing instance information
    #
    # @abstract Subclass and override for the specific insertion point flavors
    #   used by the implementation.
    def initialize(*args)
      if args.first.kind_of? Hash
        hsh = args.first
        @type = hsh[:type] || hsh['type']
      else
        @name, @type, @base_vlaue, @offsets = args
      end
    end

    # This method returns the name of the insertion point.
    #
    # @return [String] The name of the insertion point (for example, a
    #   description of a particular request parameter).
    #
    def getInsertionPointName
      @name || self.class.name
    end

    # This method returns the base value for this insertion point.
    #
    # @return [String] the base value that appears in this insertion point in
    #   the base request being scanned, or +nil+ if there is no value in the
    #   base request that corresponds to this insertion point.
    #
    # @abstract
    def getBaseValue
      @base_value
    end

    # This method is used to build a request with the specified payload placed
    # into the insertion point. Any necessary adjustments to the
    # Content-Length header will be made by the Scanner itself when the
    # request is issued, and there is no requirement for the insertion point
    # to do this.
    #
    # @note Burp's built-in scan checks do not apply any payload encoding
    #   (such as URL-encoding) when dealing with an extension-provided
    #   insertion point. Custom insertion points are responsible for
    #   performing any data encoding that is necessary given the nature and
    #   location of the insertion point.
    #
    # @param [Array<byte>] payload The payload that should be placed into the
    #   insertion point.
    # @return [Array<byte>] The resulting request.
    #
    # @todo figure out wrapping these calls (method_missing magic?)
    # @abstract
    # @api called by burp
    def buildRequest(payload)
      # ...
    end

    # This method is used to determine the offsets of the payload value within
    # the request, when it is placed into the insertion point. Scan checks may
    # invoke this method when reporting issues, so as to highlight the
    # relevant part of the request within the UI.
    #
    # @param [Array<byte>] payload The payload that should be placed into the
    #   insertion point.
    # @return [Array<Fixnum>] An int[2] array containing the start and end
    #   offsets of the payload within the request, or +nil+ if this is not
    #   applicable (for example, where the insertion point places a payload
    #   into a serialized data structure, the raw payload may not literally
    #   appear anywhere within the resulting request).
    #
    # @todo figure out wrapping these calls (method_missing magic?)
    # @abstract
    def getPayloadOffsets(payload)
      @offsets
    end

    # This method returns the type of the insertion point.
    #
    # @return [Fixnum] The type of the insertion point. Available types are
    #   defined in {Buby::ScannerInsertionPoint}.
    #
    def getInsertionPointType
      @type || INS_UNKNOWN
    end
  end
end
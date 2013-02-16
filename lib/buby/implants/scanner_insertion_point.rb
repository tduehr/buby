class Buby
  module Implants

    # This interface is used to define an insertion point for use by active
    # Scanner checks. Extensions can obtain instances of this interface by
    # registering an +IScannerCheck+, or can create instances for use by Burp's
    # own scan checks by registering an +IScannerInsertionPointProvider+.
    #
    module ScannerInsertionPoint
      INS_PARAM_URL            = 0x00;
      INS_PARAM_BODY           = 0x01;
      INS_PARAM_COOKIE         = 0x02;
      INS_PARAM_XML            = 0x03;
      INS_PARAM_XML_ATTR       = 0x04;
      INS_PARAM_MULTIPART_ATTR = 0x05;
      INS_PARAM_JSON           = 0x06;
      INS_PARAM_AMF            = 0x07;
      INS_HEADER               = 0x20;
      INS_URL_REST             = 0x21;
      INS_PARAM_NAME_URL       = 0x22;
      INS_PARAM_NAME_BODY      = 0x23;
      INS_USER_PROVIDED        = 0x40;
      INS_EXTENSION_PROVIDED   = 0x41;
      INS_UNKNOWN              = 0x7f;

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
      # @param [String] payload The payload that should be placed into the
      #   insertion point.
      # @return [String] The resulting request.
      #
      def buildRequest(payload)
        String.from_java_bytes(__buildRequest(payload.to_java_bytes))
      end


      # This method is used to determine the offsets of the payload value within
      # the request, when it is placed into the insertion point. Scan checks may
      # invoke this method when reporting issues, so as to highlight the
      # relevant part of the request within the UI.
      #
      # @param [String, Array<byte>] payload The payload that should be placed
      #   into the insertion point.
      # @return [Array<Fixnum>, nil] An int[2] array containing the start and
      #   end offsets of the payload within the request, or +nil+ if this is not
      #   applicable (for example, where the insertion point places a payload
      #   into a serialized data structure, the raw payload may not literally
      #   appear anywhere within the resulting request).
      #
      def getPayloadOffsets(payload)
        payload = payload.to_java_bytes if payload.respond_to? :to_java_bytes
        __getPayloadOffsets(payload)
      end

      # Install ourselves into the current +IScannerInsertionPoint+ java class
      # @param [IScannerInsertionPoint] point
      #
      # @todo __persistent__?
      def self.implant(point)
        unless point.implanted? || point.nil?
          pp [:implanting, point, point.class] if $DEBUG
          point.class.class_exec(point) do |point|
            a_methods = %w{
              buildRequest
              getPayloadOffsets
            }
            a_methods.each do |meth|
              alias_method "__"+meth.to_s, meth
            end
            include Buby::Implants::ScannerInsertionPoint
            a_methods.each do |meth|
              java_class.ruby_names_for_java_method(meth).each do |ruby_meth|
                define_method ruby_meth, Buby::Implants::ScannerInsertionPoint.instance_method(meth)
              end
            end
            include Buby::Implants::Proxy
          end
        end
        point
      end
    end
  end
end

class Buby
  module Implants
    # This interface is used to retrieve key details about an HTTP response.
    # Extensions can obtain an +IResponseInfo+ object for a given response by calling
    # <code>IExtensionHelpers.analyzeResponse()</code>.
    #
    module ResponseInfo
      # This method is used to obtain details of the HTTP cookies set in the
      # response.
      #
      # @return [ICookie] A list of +ICookie+ objects representing the cookies
      #   set in the response, if any.
      #
      def getCookies
        __getCookies.tap{|cookies| Buby::Implants::Cookie.implant(cookies.first)}
      end

      # Install ourselves into the current +IResponseInfo+ java class
      # @param [IResponseInfo] info
      #
      # @todo __persistent__?
      def self.implant(info)
        unless info.implanted? || info.nil?
          pp [:implanting, info, info.class] if 
          info.class.class_exec(info) do |info|
            a_methods = %w{
              getCookies
            }
            a_methods.each do |meth|
              alias_method "__"+meth.to_s, meth
            end
            include Buby::Implants::ResponseInfo
            a_methods.each do |meth|
              java_class.ruby_names_for_java_method(meth).each do |ruby_meth|
                define_method ruby_meth, Buby::Implants::ResponseInfo.instance_method(meth)
              end
            end
            include Buby::Implants::Proxy
          end
        end
        info
      end
    end
  end
end
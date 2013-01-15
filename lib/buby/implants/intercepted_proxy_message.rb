class Buby
  module Implants

    # This interface is used to represent an HTTP message that has been
    # intercepted by Burp Proxy. Extensions can register an +IProxyListener+ to
    # receive details of proxy messages using this interface.
    #
    module InterceptedProxyMessage
      # This method retrieves details of the intercepted message.
      #
      # @return [IHttpRequestResponse] object containing details of the
      # intercepted message.
      #
      # @todo IHttpRequestResponse
      def getMessageInfo
        __getMessageInfo.tap{|msg| Buby::HttpRequestResponseHelper.implant(msg)}
      end

      # Install ourselves into the current +IInterceptedProxyMessage+ java class
      # @param [IInterceptedProxyMessage] message
      #
      # @todo __persistent__?
      def self.implant(message)
        unless message.implanted? || message.nil?
          pp [:implanting, message, message.class] if 
          message.class.class_exec(message) do |message|
            a_methods = %w{
              getMessageInfo
            }
            a_methods.each do |meth|
              alias_method "__"+meth.to_s, meth
            end
            include Buby::Implants::InterceptedProxyMessage
            a_methods.each do |meth|
              java_class.ruby_names_for_java_method(meth).each do |ruby_meth|
                define_method ruby_meth, Buby::Implants::InterceptedProxyMessage.instance_method(meth)
              end
            end
            include Buby::Implants::Proxy
          end
        end
        message
      end
    end
  end
end

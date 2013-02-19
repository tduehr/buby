class Buby
  module Implants

    # This interface is used to represent an HTTP message that has been
    # intercepted by Burp Proxy. Extensions can register an +IProxyListener+ to
    # receive details of proxy messages using this interface.
    #
    module InterceptedProxyMessage
      FOLLOW_RULES              = Java::Burp::IInterceptedProxyMessage::ACTION_FOLLOW_RULES
      DO_INTERCEPT              = Java::Burp::IInterceptedProxyMessage::ACTION_DO_INTERCEPT
      DONT_INTERCEPT            = Java::Burp::IInterceptedProxyMessage::ACTION_DONT_INTERCEPT
      DROP                      = Java::Burp::IInterceptedProxyMessage::ACTION_DROP
      FOLLOW_RULES_AND_REHOOK   = Java::Burp::IInterceptedProxyMessage::ACTION_FOLLOW_RULES_AND_REHOOK
      DO_INTERCEPT_AND_REHOOK   = Java::Burp::IInterceptedProxyMessage::ACTION_DO_INTERCEPT_AND_REHOOK
      DONT_INTERCEPT_AND_REHOOK = Java::Burp::IInterceptedProxyMessage::ACTION_DONT_INTERCEPT_AND_REHOOK

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
          pp [:implanting, message, message.class] if $DEBUG
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

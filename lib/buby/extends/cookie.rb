class Buby
  module Implants
    # This interface is used to hold details about an HTTP cookie.
    #
    # @note This module is used to extend the ICookie interface implementation
    #   java class at runtime.
    module Cookie
      # This method is used to retrieve the expiration time for the cookie.
      #
      # @return [Time] The expiration time for the cookie, or +nil+ if none is
      #   set (i.e., for non-persistent session cookies).
      #
      def getExpiration
        ret = __getExpiration
        ret.nil? ret : Time.at(ret.time/1000.0)
      end

      # Install ourselves into the current +IExtensionHelpers+ java class
      # @param [ICookie] cookie instance
      #
      # @todo __persistent__?
      def self.implant(cookie)
        unless cookie.implanted? || cookie.nil?
          pp [:implanting, cookie, invocation.class] if $DEBUG
          cookie.class.class_exec(self) do
            methods = %w{
              getExpiration
            }
            methods.each do |meth|
              alias_method "__"+meth, meth
            end
            include Buby::Implants::Cookie
            methods.each do |meth|
              rewrap_java_method meth
            end
          end
        end
        cookie
      end
    end
  end
end

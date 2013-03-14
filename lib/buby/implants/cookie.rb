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
        ret.nil? ? ret : Time.at(ret.time/1000.0)
      end

      # Install ourselves into the current +ICookie+ java class
      # @param [ICookie] cookie instance
      #
      def self.implant(cookie)
        unless cookie.implanted? || cookie.nil?
          pp [:implanting, cookie, cookie.class] if $DEBUG
          cookie.class.class_exec(cookie) do |cookie|
            a_methods = %w{
              getExpiration
            }
            a_methods.each do |meth|
              pp ["__" + meth, self] if $DEBUG
              alias_method "__"+meth.to_s, meth
            end
            include Buby::Implants::Cookie
            a_methods.each do |meth|
              pp [meth, self] if $DEBUG
              java_class.ruby_names_for_java_method(meth).each do |ruby_meth|
                pp [ruby_meth, meth, self] if $DEBUG
                define_method ruby_meth, Buby::Implants::Cookie.instance_method(meth)
              end
            end
            include Buby::Implants::Proxy
          end
        end
        cookie
      end
    end
  end
end

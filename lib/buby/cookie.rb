require 'cgi'

class Buby
  # This class is used to hold details about an HTTP cookie. Implements the
  # +burp.ICookie+ interface
  #
  class Cookie < CGI::Cookie
    include Java::Burp::ICookie

    # This method is used to retrieve the domain for which the cookie is in
    # scope. 
    #
    # @return [String] The domain for which the cookie is in scope.
    def getDomain
      @domain
    end

    # This method is used to retrieve the expiration time for the cookie.
    #
    # @return [java.util.Date] The expiration time for the cookie, or +nil+ if
    #   none is set (i.e., for non-persistent session cookies).
    #
    def getExpiration; @expires; end

    # This method is used to retrieve the name of the cookie.
    #
    # @return [String] The name of the cookie.
    #
    def getName; @name; end

    # This method is used to retrieve the value of the cookie.
    # 
    # @return [String] The value of the cookie.
    #
    def getValue; join("&"); end
  end
end

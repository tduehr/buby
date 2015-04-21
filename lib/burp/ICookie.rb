# @!parse
#   module Burp
#     # This interface is used to hold details about an HTTP cookie.
#     #
#     module ICookie
#       # This method is used to retrieve the domain for which the cookie is in
#       # scope.
#       #
#       # @note For cookies that have been analyzed from responses (by calling
#       #   {IExtensionHelpers#analyzeResponse} and then
#       #   {IResponseInfo#getCookies}, the domain will be +nil+ if the
#       #   response did not explicitly set a domain attribute for the cookie.
#       #
#       # @return [String] The domain for which the cookie is in scope.
#       #
#       def getDomain; end
#       alias get_domain getDomain
#
#       # This method is used to retrieve the expiration time for the cookie.
#       #
#       # @return [Date] The expiration time for the cookie, or +nil+ if none
#       #   is set (i.e., for non-persistent session cookies).
#       #
#       def getExpiration; end
#       alias get_expiration getExpiration
#
#       # This method is used to retrieve the name of the cookie.
#       #
#       # @return [String] The name of the cookie.
#       #
#       def getName; end
#       alias get_name getName
#
#       # This method is used to retrieve the value of the cookie.
#       #
#       # @return [String] The value of the cookie.
#       #
#       def getValue; end
#       alias get_value getValue
#     end
#   end

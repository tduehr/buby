# @!parse
#   module Burp
#     # This interface is used to hold details about an Intruder attack.
#     #
#     module IIntruderAttack
#       # This method is used to retrieve the HTTP service for the attack.
#       #
#       # @return [IHttpService] The HTTP service for the attack.
#       #
#       def getHttpService; end
#       alias get_http_service getHttpService
#
#       # This method is used to retrieve the request template for the attack.
#       #
#       # @return [byte[]] The request template for the attack.
#       #
#       def getRequestTemplate; end
#       alias get_request_template getRequestTemplate
#     end
#   end

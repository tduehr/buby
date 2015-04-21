# @!parse
#   module Burp
#     # This interface is used to provide details about an HTTP service, to
#     # which HTTP requests can be sent.
#     #
#     module IHttpService
#       # This method returns the hostname or IP address for the service.
#       #
#       # @return [String] The hostname or IP address for the service.
#       #
#       def getHost; end
#       alias get_host getHost
#       alias host getHost
#
#       # This method returns the port number for the service.
#       #
#       # @return [int] The port number for the service.
#       #
#       def getPort; end
#       alias get_port getPort
#       alias port getPort
#
#       # This method returns the protocol for the service.
#       #
#       # @return [String] The protocol for the service. Expected values are
#       #   "http" or "https".
#       #
#       def getProtocol; end
#       alias get_protocol getProtocol
#       alias protocol getProtocol
#     end
#   end

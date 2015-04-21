# @!parse
#   module Burp
#     # Extensions can implement this interface and then call
#     # {IBurpExtenderCallbacks#registerProxyListener} to register a Proxy
#     # listener. The listener will be notified of requests and responses being
#     # processed by the Proxy tool.
#     #
#     # Extensions can perform custom analysis or modification of these
#     # messages, and control in-UI message interception, by registering a
#     # proxy listener.
#     #
#     module IProxyListener
#       # This method is invoked when an HTTP message is being processed by the
#       # Proxy.
#       #
#       # @param [boolean] messageIsRequest Indicates whether the HTTP message
#       #   is a request or a response.
#       # @param [IInterceptedProxyMessage] message An object that extensions
#       #   can use to query and update details of the message, and control
#       #   whether the message should be intercepted and displayed to the user
#       #   for manual review or modification.
#       #
#       # @return [void]
#       #
#       def processProxyMessage(messageIsRequest, message); end
#       alias process_proxy_message processProxyMessage
#     end
#   end

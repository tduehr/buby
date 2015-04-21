# @!parse
#   module Burp
#     # This interface is used to represent an HTTP message that has been
#     # intercepted by Burp Proxy. Extensions can register an {IProxyListener}
#     # to receive details of proxy messages using this interface.
#     #
#     module IInterceptedProxyMessage
#       # This action causes Burp Proxy to follow the current interception
#       # rules to determine the appropriate action to take for the message.
#       #
#       # # ACTION_FOLLOW_RULES = 0;
#
#       # This action causes Burp Proxy to present the message to the user for
#       # manual review or modification.
#       #
#       # # ACTION_DO_INTERCEPT = 1;
#
#       # This action causes Burp Proxy to forward the message to the remote
#       # server or client, without presenting it to the user.
#       #
#       # # ACTION_DONT_INTERCEPT = 2;
#
#       # This action causes Burp Proxy to drop the message.
#       #
#       # # ACTION_DROP = 3;
#
#       # This action causes Burp Proxy to follow the current interception
#       # rules to determine the appropriate action to take for the message,
#       # and then make a second call to processProxyMessage.
#       #
#       # # ACTION_FOLLOW_RULES_AND_REHOOK = 0x10;
#
#       # This action causes Burp Proxy to present the message to the user for
#       # manual review or modification, and then make a second call to
#       # processProxyMessage.
#       #
#       # # ACTION_DO_INTERCEPT_AND_REHOOK = 0x11;
#
#       # This action causes Burp Proxy to skip user interception, and then
#       # make a second call to processProxyMessage.
#       #
#       # # ACTION_DONT_INTERCEPT_AND_REHOOK = 0x12;
#
#       # This method retrieves a unique reference number for this
#       # request/response.
#       #
#       # @return [int] An identifier that is unique to a single
#       #   request/response pair. Extensions can use this to correlate details
#       #   of requests and responses and perform processing on the response
#       #   message accordingly.
#       #
#       def getMessageReference; end
#       alias get_message_reference getMessageReference
#       alias message_reference getMessageReference
#
#       # This method retrieves details of the intercepted message.
#       #
#       # @return [IHttpRequestResponse] An {IHttpRequestResponse} object
#       #   containing details of the intercepted message.
#       #
#       def getMessageInfo; end
#       alias get_message_info getMessageInfo
#       alias message_info getMessageInfo
#
#       # This method retrieves the currently defined interception action. The
#       # default action is +ACTION_FOLLOW_RULES+. If multiple proxy listeners
#       # are registered, then other listeners may already have modified the
#       # interception action before it reaches the current listener. This
#       # method can be used to determine whether this has occurred.
#       #
#       # @return [int] The currently defined interception action. Possible
#       #   values are defined within this interface.
#       #
#       def getInterceptAction; end
#       alias get_intercept_action getInterceptAction
#       alias intercept_action getInterceptAction
#
#       # This method is used to update the interception action.
#       #
#       # @param [int] interceptAction The new interception action. Possible
#       #   values are defined within this interface.
#       #
#       # @return [void]
#       #
#       def setInterceptAction(interceptAction); end
#       alias set_intercept_action setInterceptAction
#       alias intercept_action= setInterceptAction
#
#       # This method retrieves the name of the Burp Proxy listener that is
#       # processing the intercepted message.
#       #
#       # @return [String] The name of the Burp Proxy listener that is
#       #   processing the intercepted message. The format is the same as that
#       #   shown in the Proxy Listeners UI - for example, "127.0.0.1:8080".
#       #
#       def getListenerInterface; end
#       alias get_listener_interface getListenerInterface
#       alias listener_interface getListenerInterface
#
#       # This method retrieves the client IP address from which the request
#       # for the intercepted message was received.
#       #
#       # @return [InetAddress] The client IP address from which the request
#       #   for the intercepted message was received.
#       #
#       def getClientIpAddress; end
#       alias get_client_ip_address getClientIpAddress
#       alias client_ip_address getClientIpAddress
#     end
#   end

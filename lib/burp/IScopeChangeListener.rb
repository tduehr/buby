# @!parse
#   module Burp
#     # Extensions can implement this interface and then call
#     # {IBurpExtenderCallbacks#registerScopeChangeListener} to register a
#     # scope change listener. The listener will be notified whenever a change
#     # occurs to Burp's suite-wide target scope.
#     #
#     module IScopeChangeListener
#       # This method is invoked whenever a change occurs to Burp's suite-wide
#       # target scope.
#       #
#       # @return [void]
#       #
#       def scopeChanged; end
#       alias scope_changed scopeChanged
#     end
#   end

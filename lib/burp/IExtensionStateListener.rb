# @!parse
#   module Burp
#     # Extensions can implement this interface and then call
#     # {IBurpExtenderCallbacks#registerExtensionStateListener} to register an
#     # extension state listener. The listener will be notified of changes to
#     # the extension's state.
#     #
#     # @note Any extensions that start background threads or open system
#     #   resources (such as files or database connections) should register a
#     #   listener and terminate threads / close aaresources when the extension
#     #   is unloaded.
#     #
#     module IExtensionStateListener
#       # This method is called when the extension is unloaded.
#       #
#       # @return [void]
#       #
#       def extensionUnloaded; end
#     end
#   end

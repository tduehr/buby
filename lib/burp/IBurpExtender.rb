# @!parse
#   module Burp
#     # Main entry point for BurpSuite entensions.
#     module IBurpExtender
#       # This method is invoked when the extension is loaded. It registers an
#       # instance of the IBurpExtenderCallbacks interface, providing methods
#       # that may be invoked by the extension to perform various actions.
#       #
#       # @param [IBurpExtenderCallbacks] callbacks
#       #
#       def registerExtenderCallbacks(callbacks); end
#       alias register_extender_callbacks registerExtenderCallbacks
#     end
#   end

# @!parse
#   module Burp
#     # This interface is used to provide Burp with details of a custom tab
#     # that will be added to Burp's UI, using a method such as
#     # {IBurpExtenderCallbacks#addSuiteTab}.
#     #
#     module ITab
#       # Burp uses this method to obtain the caption that should appear on the
#       # custom tab when it is displayed.
#       #
#       # @return [String] The caption that should appear on the custom tab
#       #   when it is displayed.
#       #
#       def getTabCaption; end
#       alias get_tab_caption getTabCaption
#       alias tab_caption getTabCaption
#
#       # Burp uses this method to obtain the component that should be used as
#       # the contents of the custom tab when it is displayed.
#       #
#       # @return [Component] The component that should be used as the contents
#       #   of the custom tab when it is displayed.
#       #
#       def getUiComponent; end
#       alias get_ui_component getUiComponent
#       alias ui_component getUiComponent
#     end
#   end

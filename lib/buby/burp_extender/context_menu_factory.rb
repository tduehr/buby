require 'buby/burp_extender/context_menu'

class BurpExtender
  # @api private
  class ContextMenuFactory
    attr_accessor :burp
    include Java::Burp::IContextMenuFactory
    def initialize burp_extender
      @burp = burp_extender
    end

    def createMenuItems invocation
      pp [:createMenuItems, invocation] if $DEBUG
      [BurpExtender::ContextMenu.new(@burp, invocation)]
    end
  end
end

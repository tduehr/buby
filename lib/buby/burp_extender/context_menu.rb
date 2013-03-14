require 'buby/burp_extender/context_menu_item'

# @api private
class BurpExtender
  # @api private
  class ContextMenu < Java::JavaxSwing::JMenu
    attr_accessor :burp, :invocation
    def initialize burp_extender, invocation
      @burp = burp_extender
      @invocation = invocation
      super 'Buby'

      if @burp.frame
        self.add(ContextMenuItem.new('Move console to tab', @burp, @invocation) do |event|
          burp = event.source.burp
          invocation = event.source.invocation
          burp.move_to_tab
        end)
      else
        self.add(ContextMenuItem.new('Move console to window', @burp, @invocation) do |event|
          burp = event.source.burp
          invocation = event.source.invocation
          burp.move_to_window
        end)

      end
    end
  end
end

class BurpExtender
  # @api private
  class ConsoleFrame < Java::JavaxSwing::JFrame
    attr_accessor :burp, :pane
    def initialize(burp_extender, pane, opts = {}, &block)
      @burp = burp_extender
      @pane = pane

      blck = lambda do |event|
        if event.getID == Java::JavaAwtEvent::WindowEvent::WINDOW_CLOSING
          @pane.tar.shutdown
          self.dispose
        end
      end

      super(opts[:title] || 'JRuby IRB Console (tab will autocomplete)')
      set_size(*(opts[:size] || [700, 600]))
      content_pane.add(@pane)
      addWindowStateListener &blck
      addWindowListener &blck

      if block_given?
        addWindowStateListener &block
        addWindowListener &block
      end

      @burp.callbacks.customizeUiComponent self
      Java::JavaAwt::EventQueue.invoke_later {
        self.visible = true
      }
    end
  end
end

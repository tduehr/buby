class BurpExtender
  # @api private
  class JMenuItem < Java::JavaxSwing::JMenuItem
    attr_accessor :burp
    def initialize text, burp_extender, &block
      super text
      @burp = burp_extender

      addActionListener &block
    end
  end
end

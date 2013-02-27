class BurpExtender
  class ContextMenuItem < javax.swing.JMenuItem
    attr_accessor :invocation, :burp
    def initialize text, burp_extender, invocation, &block
      super text
      @invocation = invocation
      @burp = burp_extender

      addActionListener &block
    end
  end
end
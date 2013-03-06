class BurpExtender
  # @api private
  class JMenu < Java::JavaxSwing::JMenu
    attr_accessor :burp
    def initialize burp_extender, name = nil
      name ||= burp_extender.handler.class.name
      @burp = burp_extender
      super name
    end
  end
end

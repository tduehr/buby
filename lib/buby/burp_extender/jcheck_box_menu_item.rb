class BurpExtender
  class JCheckBoxMenuItem < Java::JavaxSwing::JCheckBoxMenuItem
    attr_accessor :burp
    def initialize(burp_extender, *args, &block)
      super *args
      @burp = burp_extender
      if block_given?
        addActionListener &block
      end
    end
  end
end
class Buby
  # This interface is used for custom Intruder payload generators. Extensions
  # that have registered an +IIntruderPayloadGeneratorFactory+ must return a new
  # instance of this interface when required as part of a new Intruder attack.
  #
  class IntruderPayloadGenerator
    include Java::Burp::IIntruderPayloadGenerator
    include Java::Burp::IIntruderPayloadGeneratorFactory

    # (see Buby::IntruderPayloadGeneratorFactory#getGeneratorName)
    def self.getGeneratorName; self.name.to_java_string; end

    # {include:Buby::IntruderPayloadGeneratorFactory#createNewInstance}
    # @param (see Buby::IntruderPayloadGeneratorFactory#createNewInstance)
    # @return (see #initialize)
    def self.createNewInstance(attack)
      Buby::Implants::IntruderAttack.implant(attack)
      self.new(attack)
    end

    # @param (see Buby::IntruderPayloadGeneratorFactory#createNewInstance)
    def initialize(attack)
      @attack = attack
    end

    # This method is used by Burp to determine whether the payload generator is
    # able to provide any further payloads.
    #
    # @return [Boolean] Extensions should return +false+ when all the available
    #   payloads have been used up, otherwise +true+.
    #
    # @abstract
    def hasMorePayloads; end
    # (see #hasMorePayloads)
    def more_payloads?; hasMorePayloads; end

    # This method is used by Burp to obtain the value of the next payload.
    #
    # @param [Array<byte>] baseValue The base value of the current payload
    #   position. This value may be +nil+ if the concept of a base value is not
    #   applicable (e.g. in a battering ram attack).
    # @return [Array<byte>] The next payload to use in the attack.
    #
    # @abstract Call super to get +baseValue+ as a +String+. Implementation's
    #   responsibility to return byte array.
    # @deprecated This will become a raw version/proxied version pair like {ContextMenuFactory#createMenuItems} in 2.0.
    def getNextPayload(baseValue)
      ret = baseValue
      baseValue = String.from_java_bytes(baseValue) if baseValue
      ret
    end

    # This method is used by Burp to reset the state of the payload generator so
    # that the next call to {#getNextPayload} returns the first payload again.
    # This method will be invoked when an attack uses the same payload generator
    # for more than one payload position, for example in a sniper attack.
    #
    # @abstract
    def reset; end
  end
end
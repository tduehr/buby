class Buby

  # Extensions can implement this interface and then call
  # {Buby#registerIntruderPayloadGeneratorFactory} to register a factory for
  # custom Intruder payloads.
  #
  # @see IntruderPayloadGenerator
  class IntruderPayloadGeneratorFactory
    include Java::Burp::IIntruderPayloadGeneratorFactory

    # This method is used by Burp to obtain the name of the payload generator.
    # This will be displayed as an option within the Intruder UI when the user
    # selects to use extension-generated payloads.
    #
    # @return [String] The name of the payload generator.
    #
    def getGeneratorName; self.class.name.to_java_string; end

    # This method is used by Burp when the user starts an Intruder attack that
    # uses this payload generator.
    #
    # @param [IIntruderAttack] attack object that can be queried to obtain
    #   details about the attack in which the payload generator will be used.
    # @return [IIntruderPayloadGenerator] A new payload generator for the
    #   attack.
    #
    # @abstract
    # @deprecated This will become a raw version/proxied version pair like {ContextMenuFactory#createMenuItems} in 2.0.
    def createNewInstance(attack)
      Buby::Implants::IntruderAttack.implant(attack)
    end
  end
end
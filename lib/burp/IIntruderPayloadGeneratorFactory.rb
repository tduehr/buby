# @!parse
#   module Burp
#     # Extensions can implement this interface and then call
#     # {IBurpExtenderCallbacks#registerIntruderPayloadGeneratorFactory} to
#     # register a factory for custom Intruder payloads.
#     #
#     module IIntruderPayloadGeneratorFactory
#       # This method is used by Burp to obtain the name of the payload
#       # generator. This will be displayed as an option within the Intruder UI
#       # when the user selects to use extension-generated payloads.
#       #
#       # @return [String] The name of the payload generator.
#       #
#       def getGeneratorName; end
#       alias get_generator_name getGeneratorName
#       alias generator_name getGeneratorName
#
#       # This method is used by Burp when the user starts an Intruder attack
#       # that uses this payload generator.
#       #
#       # @param [IIntruderAttack] attack An {IIntruderAttack} object that can
#       #   be queried to obtain details about the attack in which the payload
#       #   generator will be used.
#       #
#       # @return [IIntruderPayloadGenerator] A new instance of
#       #   {IIntruderPayloadGenerator} that will be used to generate payloads
#       #   for the attack.
#       #
#       def createNewInstance(attack); end
#       alias create_new_instance createNewInstance
#     end
#   end

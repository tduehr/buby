# @!parse
#   module Burp
#     # This interface is used for custom Intruder payload generators.
#     # Extensions that have registered an {IIntruderPayloadGeneratorFactory}
#     # must return a new instance of this interface when required as part of a
#     # new Intruder attack.
#     #
#     module IIntruderPayloadGenerator
#       # This method is used by Burp to determine whether the payload
#       # generator is able to provide any further payloads.
#       #
#       # @return [boolean] Extensions should return +false+ when all the
#       #   available payloads have been used up, otherwise +true+.
#       #
#       def hasMorePayloads; end
#       alias has_more_payloads hasMorePayloads
#       alias more_payloads? hasMorePayloads
#
#       # This method is used by Burp to obtain the value of the next payload.
#       #
#       # @param [byte[], nil] baseValue The base value of the current payload
#       #   position. This value may be +nil+ if the concept of a base value is
#       #   not applicable (e.g. in a battering ram attack).
#       #
#       # @return [byte[]] The next payload to use in the attack.
#       #
#       def getNextPayload(baseValue); end
#       alias get_next_payload getNextPayload
#       alias next_payload getNextPayload
#
#       # This method is used by Burp to reset the state of the payload
#       # generator so that the next call to {getNextPayload} returns the first
#       # payload again. This method will be invoked when an attack uses the
#       # same payload generator for more than one payload position, for
#       # example in a sniper attack.
#       #
#       # @return [void]
#       #
#       def reset; end
#     end
#   end

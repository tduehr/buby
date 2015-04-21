# @!parse
#   module Burp
#   # Extensions can implement this interface and then call
#   # {IBurpExtenderCallbacks#registerIntruderPayloadProcessor} to register a
#   # custom Intruder payload processor.
#   #
#   module IIntruderPayloadProcessor
#       # This method is used by Burp to obtain the name of the payload
#       # processor. This will be displayed as an option within the Intruder UI
#       # when the user selects to use an extension-provided payload processor.
#       #
#       # @return [String] The name of the payload processor.
#       #
#       def getProcessorName; end
#       alias get_processor_name getProcessorName
#       alias processor_name getProcessorName
#
#       # This method is invoked by Burp each time the processor should be
#       # applied to an Intruder payload.
#       #
#       # @param [byte[]] currentPayload The value of the payload to be
#       #   processed.
#       # @param [byte[]] originalPayload The value of the original payload
#       #   prior to processing by any already-applied processing rules.
#       # @param [byte[]] baseValue The base value of the payload position,
#       #   which will be replaced with the current payload.
#       #
#       # @return [byte[]] The value of the processed payload. This may be
#       #   +nil+ to indicate that the current payload should be skipped, and
#       #   the attack will move directly to the next payload.
#       #
#       def processPayload(currentPayload, originalPayload, baseValue); end
#       alias process_payload processPayload
#     end
#   end

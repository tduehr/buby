class Buby
  # Extensions can implement this interface and then call
  # {Buby#registerIntruderPayloadProcessor} to register a custom Intruder
  # payload processor.
  #
  # @todo voodoo function wrapping?
  class IntruderPayloadProcessor
    include Java::Burp::IntruderPayloadProcessor

    # This method is used by Burp to obtain the name of the payload processor.
    # This will be displayed as an option within the Intruder UI when the user
    # selects to use an extension-provided payload processor.
    #
    # @return [String] The name of the payload processor.
    #
    def getProcessorName; self.class.name; end

    # This method is invoked by Burp each time the processor should be applied
    # to an Intruder payload.
    #
    # @param [Array[byte]] currentPayload The value of the payload to be
    #   processed.
    # @param [Array[byte]] originalPayload The value of the original payload
    #   prior to processing by any already-applied processing rules.
    # @param [Array[byte]] baseValue The base value of the payload position,
    #   which will be replaced with the current payload.
    # @return The value of the processed payload. This may be +nil+ to
    #   indicate that the current payload should be skipped, and the attack
    #   will move directly to the next payload.
    #
    def processPayload(currentPayload, originalPayload, baseValue)
      currentPayload = String.from_java_bytes currentPayload
      originalPayload = String.from_java_bytes originalPayload
      baseValue = String.from_java_bytes baseValue
      nil
    end
  end
end

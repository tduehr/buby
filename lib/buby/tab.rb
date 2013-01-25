class Buby
  # This interface is used to provide Burp with details of a custom tab that
  # will be added to Burp's UI, using a method such as {Buby#addSuiteTab}.
  #
  # @abstract
  class Tab
    include Java::Burp::ITab
    attr_accessor :caption, :component

    def initialize(caption = nil, component = nil)
      @caption = caption || self.class.name
      @component = component
    end

    # Burp uses this method to obtain the caption that should appear on the
    # custom tab when it is displayed.
    #
    # @return [String] The caption that should appear on the custom tab when it
    #   is displayed.
    #
    def getTabCaption
      pp [:got_getTabCaption] if $DEBUG
      @caption.to_s
    end

    # Burp uses this method to obtain the component that should be used as the
    # contents of the custom tab when it is displayed.
    #
    # @return [java.awt.Component] The component that should be used as the
    #   contents of the custom tab when it is displayed.
    #
    def getUiComponent
      pp [:got_getUiComponent] if $DEBUG
      @component
    end
  end
end

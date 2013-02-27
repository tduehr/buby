require 'buby/version'

class BurpExtender
  class ConsoleTab
    include Java::Burp::ITab
    attr_accessor :ui_component, :tab_caption
    CAPTION = "Buby v#{Buby::Version::STRING}"

    def initialize component, caption = nil
      @ui_component = component
      @tab_caption = caption || CAPTION
    end
  end
end
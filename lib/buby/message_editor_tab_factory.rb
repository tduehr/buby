class Buby
  # Extensions can implement this interface and then call
  # {Buby#registerMessageEditorTabFactory} to register a factory for custom
  # message editor tabs. This allows extensions to provide custom rendering or
  # editing of HTTP messages, within Burp's own HTTP editor.
  #
  # @abstract
  class MessageEditorTabFactory
    # Burp will call this method once for each HTTP message editor, and the
    # factory should provide a new instance of an +IMessageEditorTab+ object.
    #
    # @param [IMessageEditorController] controller An object which the new tab
    #   can query to retrieve details about the currently displayed message.
    #   This may be +nil+ for extension-invoked message editors where the
    #   extension has not provided an editor controller.
    # @param [Boolean] editable Indicates whether the hosting editor is editable
    #   or read-only.
    # @return [IMessageEditorTab] A new tab for use within the message editor.
    #
    # @abstract subclass and call super
    def createNewInstance(controller, editable)
      Buby::Implants::MessageEditorController.implant controller
      nil
    end
  end
end

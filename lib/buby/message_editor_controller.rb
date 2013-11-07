class Buby
  # This interface is used by an +IMessageEditor+ to obtain details about the
  # currently displayed message. Extensions that create instances of Burp's HTTP
  # message editor can optionally provide an implementation of
  # +IMessageEditorController+, which the editor will invoke when it requires
  # further information about the current message (for example, to send it to
  # another Burp tool). Extensions that provide custom editor tabs via an
  # +IMessageEditorTabFactory+ will receive a reference to an
  # +IMessageEditorController+ object for each tab instance they generate, which
  # the tab can invoke if it requires further information about the current
  # message.
  #
  class MessageEditorController
    include Java::Burp::IMessageEditorController

    # This method is used to retrieve the HTTP service for the current message.
    #
    # @return [IHttpService] The HTTP service for the current message.
    #
    # @abstract
    def getHttpService; raise NotImplementedError; end

    # This method is used to retrieve the HTTP request associated with the
    # current message (which may itself be a response).
    #
    # @return [Array<byte>] The HTTP request associated with the current
    #   message.
    #
    # @abstract
    # @deprecated This will become a raw version/proxied version pair like {ContextMenuFactory#createMenuItems} in 2.0.
    def getRequest; raise NotImplementedError; end

    # This method is used to retrieve the HTTP response associated with the
    # current message (which may itself be a request).
    #
    # @return [Array<byte>] The HTTP response associated with the current
    #   message.
    #
    # @abstract
    # @deprecated This will become a raw version/proxied version pair like {ContextMenuFactory#createMenuItems} in 2.0.
    def getResponse; raise NotImplementedError; end
  end
end

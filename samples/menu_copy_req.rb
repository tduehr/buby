module CopyRequest
  def copyRequest(req)
    req = case
    when req.is_a?(Numeric)
      # offset to match UI
      self.proxy_history[req-1].req_str
    when req.kind_of?(String)
      req
    when (req.respond_to?(:java_class) and req.java_class.to_s == "[B")
      String.from_java_bytes(req)
    when req.respond_to?(:req_str)
      req.req_str
    else
      warn "unknown request type... ducking"
      req
    end
    
    java.awt.Toolkit.getDefaultToolkit.getSystemClipboard.setContents(java.awt.datatransfer.StringSelection.new(req), nil)
    req
  end
  alias copy_request copyRequest
  
  def init_CopyRequest
    CopyRequestHandler.init_handler("Copy request(s)", self)
  end
end

module CopyRequestHandler
  class << self
    attr_accessor :_burp
    attr_reader :menuItemCaption
  end
  
  def self.init_handler(menuItemCaption, _burp = $burp)
    @menuItemCaption = menuItemCaption
    @_burp = _burp
    @_burp.registerMenuItem(menuItemCaption, self)
  end
  
  def self.menuItemClicked(menuItemCaption, messageInfo)
    messageInfo = Buby::HttpRequestResponseList.new(messageInfo).map{|x| x.req_str}.join("\r\n\r\n#{'='*50}\r\n\r\n")
    java.awt.Toolkit.getDefaultToolkit.getSystemClipboard.setContents(java.awt.datatransfer.StringSelection.new(messageInfo), nil)
  end
end

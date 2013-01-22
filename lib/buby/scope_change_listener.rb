class Buby
  # Extensions can implement this interface and then call
  # {Buby#registerScopeChangeListener} to register a scope change listener. The
  # listener will be notified whenever a change occurs to Burp's suite-wide
  # target scope.
  #
  # @todo improve listener classes with 1.9 instance_exec goodness next version
  def ScopeChangeListener
    include Java::Burp::IScopeChangeListener

    # This method is invoked whenever a change occurs to Burp's suite-wide
    # target scope.
    #
    # @abstract
    def scopeChanged
      pp [:got_scopeChanged] if $DEBUG
    end
  end
end


require 'rubygems'
require 'buby'
require 'drb'

module DrbBuby
  attr_reader :drb_server

  def evt_register_callbacks(cb)
    super(cb)
#    cb.issueAlert("[DrbBuby] Service on: #{@drb_server.uri}")
  end

  def init_DrbBuby
    ## want to bind the DRb service on a specific socket?
    uri ='druby://127.0.0.1:9999'
    ## or let it choose one automatically:
    #  uri = nil 
    @drb_server = DRb.start_service uri, self
    puts "[DrbBuby] Service on: #{@drb_server.uri}"
    self.alert("[DrbBuby] Service on: #{@drb_server.uri}")
  end
end

if __FILE__ == $0
  $burp = Buby.new
  $burp.extend(DrbBuby)
  $burp.start_burp()
  $burp.init_DrbBuby
end


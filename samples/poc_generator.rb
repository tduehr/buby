require 'uri'
require 'htmlentities'

# This set up as a buby module extension. You can load it from the CLI when 
# launching buby as follows:
#
#   buby -r csrf_poc_generator.rb -e CsrfPocGenerator -i
# 
module PocGenerator
  HEX = %w{0 1 2 3 4 5 6 7 8 9 a b c d e f}

  # Take a HTTP POST string and convert it to HTML proof of concept with a
  # form full of hidden variables that gets auto-submitted on load. 
  #
  # Especially handy for burp since you don't always know whether what you're 
  # playing with in repeater will actually work in the browser. Also handy for 
  # testing reflected/stored XSS if the request happens to require a POST. 
  #
  # Handles www-form-urlencoded as well as multi-part. Note if your multi-part 
  # data has any files in it, they'll just get jammed into a hidden var with 
  # the rest. This may or may not be what you actually want.
  #
  # @param req can be a index into proxy_history, string, java byte array, or 
  # HttpRequestResponse object
  #
  # @param options:
  #   :uri  = uri to set form action to (default - auto)
  #   :meth = form http method (default - POST)
  #   :enc  = form enctype (default - 'application/www-form-urlencoded')
  #   :host = override 'host' in uri with this. (default - auto)
  #   :scheme = override 'scheme' in uri with this. (default - 'http')
  #   :port = override 'port' in uri with this. (default - blank)
  #
  # The URI, host scheme, and port are all automatically pulled from req if
  # it is a HttpRequest. Otherwise, the code will attempt to gather this info
  # from the Host: header and HTTP action. Note that in the latter case, the
  # determination of http/https is impossible, so you'll want to specify the
  # scheme
  def post_to_poc(req, opts = {})
    uri  = opts[:uri]
    meth = opts[:meth] || "POST"
    enc  = opts[:enc] || opts[:encoding] || 'application/www-form-urlencoded'
    host = opts[:host]
    scheme = opts[:scheme]
    port = opts[:port]

    reqstr =
      if req.kind_of? String
        req
      elsif req.respond_to? :java_class and req.java_class.to_s == "[B"
        String.from_java_bytes 
      elsif req.kind_of? Numeric
        req = getProxyHistory()[req]
        uri ||= req.uri
        req.req_str
      elsif req.respond_to?(:req_str)
        req.req_str 
      end

    params = getParameters(reqstr).to_a.select {|x| x[2] == "body parameter"}.map {|p| [p[0], p[1].chomp]}
    headers = getHeaders(reqstr).to_a
    verb, action, vers = headers.first.split(/\s+/, 3)

    if headers.grep(/^content-type: application\/(?:x-)?www-form-urlencoded(?:\W|$)/i)
      params = params.map do |p| 
        p.map do |f|
          f.gsub(/%[a-f0-9]{2}/i) do |x| 
            ((HEX.index(x[1,1].downcase) << 4) + HEX.index(x[2,1].downcase)).chr
          end
        end
      end
    end

    if uri.nil?  
      uri =
        if req.respond_to? :uri
          uri = req.uri
        else
          uri = URI.parse(action)
        end
    elsif uri.is_a? String
      uri = URI.parse(action)
    end

    if opts[:host]
      uri.host = host
      uri.scheme = scheme if scheme
    elsif host.nil? and hhost = headers.grep(/host: (.*)$/i){|h| $1 }.first
      uri.host = hhost
      uri.scheme = scheme || 'http'
    else
      uri.scheme = scheme if scheme
    end

    uri.port = port if port

    ret = %{<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
<html><head></head>
<body>
   <form name="doit_form" method="#{meth.to_s.upcase}" action=#{uri.to_s.inspect} enctype=#{enc.inspect}>
}

    coder = HTMLEntities.new
    params.each do |p|
      name = coder.encode(p[0]).inspect
      val  = coder.encode(p[1]).inspect
      ret << "        <input type=\"hidden\" name=#{name} value=#{val} />\n"
    end

    ret << %{
    <input type="submit" value="click me if this doesnt redirect'" />
  </form>
  <script> document.doit_form.submit(); </script>
</body>
</html>}

    return ret
  end

  def init_CsrfPocGenerator
    # nop
  end
end


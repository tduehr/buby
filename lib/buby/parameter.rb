class Buby
  module Parameter
    autoload :Base, 'buby/parameter/base'
    autoload :Url, 'buby/parameter/url'
    autoload :Body, 'buby/parameter/body'
    autoload :Cookie, 'buby/parameter/cookie'
    PARAM_URL = 0
    PARAM_BODY = 1
    PARAM_COOKIE = 2
    PARAM_XML = 3
    PARAM_XML_ATTR = 4
    PARAM_MULTIPART_ATTR = 5
    PARAM_JSON = 6
  end
end

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

    # This method constructs an +IParameter+ object based on the details
    #   provided.
    #
    # @param [String] name The parameter name.
    # @param [String] value The parameter value.
    # @param [Fixnum, #to_s] ptype The parameter type, as defined in the
    #   +IParameter+ interface.
    # @return [IParameter] object based on the details provided.
    def self.build_parameter(name, value, ptype)
      $burp.helpers.buildParameter(name, value, ptype)
    end
  end
end

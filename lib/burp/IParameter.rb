# @!parse
#   module Burp
#     # This interface is used to hold details about an HTTP request parameter.
#     #
#     module IParameter
#
#       # Used to indicate a parameter within the URL query string.
#       #
#       # # PARAM_URL = 0;
#
#       # Used to indicate a parameter within the message body.
#       #
#       # # PARAM_BODY = 1;
#
#       # Used to indicate an HTTP cookie.
#       #
#       # # PARAM_COOKIE = 2;
#
#       # Used to indicate an item of data within an XML structure.
#       #
#       # # PARAM_XML = 3;
#
#       # Used to indicate the value of a tag attribute within an XML
#       # structure.
#       #
#       # # PARAM_XML_ATTR = 4;
#
#       # Used to indicate the value of a parameter attribute within a
#       # multi-part message body (such as the name of an uploaded file).
#       #
#       # # PARAM_MULTIPART_ATTR = 5;
#
#       # Used to indicate an item of data within a JSON structure.
#       #
#       # # PARAM_JSON = 6;
#
#       # This method is used to retrieve the parameter type.
#       #
#       # @return [byte] The parameter type. The available types are defined
#       #   within this interface.
#       #
#       def getType; end
#       alias get_type getType
#       alias type getType
#
#       # This method is used to retrieve the parameter name.
#       #
#       # @return [String] The parameter name.
#       #
#       def getName; end
#       alias get_name getName
#       alias name getName
#
#       # This method is used to retrieve the parameter value.
#       #
#       # @return [String] The parameter value.
#       #
#       def getValue; end
#       alias get_value getValue
#       alias value getValue
#
#       # This method is used to retrieve the start offset of the parameter
#       # name within the HTTP request.
#       #
#       # @return [int] The start offset of the parameter name within the HTTP
#       #   request, or -1 if the parameter is not associated with a specific
#       #   request.
#       #
#       def getNameStart; end
#       alias get_name_start getNameStart
#       alias name_start getNameStart
#
#       # This method is used to retrieve the end offset of the parameter name
#       # within the HTTP request.
#       #
#       # @return [int] The end offset of the parameter name within the HTTP
#       #   request, or -1 if the parameter is not associated with a specific
#       #   request.
#       #
#       def getNameEnd; end
#       alias get_name_end getNameEnd
#       alias name_end getNameEnd
#
#       # This method is used to retrieve the start offset of the parameter
#       # value within the HTTP request.
#       #
#       # @return [int] The start offset of the parameter value within the HTTP
#       #   request, or -1 if the parameter is not associated with a specific
#       #   request.
#       #
#       def getValueStart; end
#       alias get_value_start getValueStart
#       alias value_start getValueStart
#
#       # This method is used to retrieve the end offset of the parameter value
#       # within the HTTP request.
#       #
#       # @return [int] The end offset of the parameter value within the HTTP
#       #   request, or -1 if the parameter is not associated with a specific
#       #   request.
#       #
#       def getValueEnd; end
#       alias get_value_end getValueEnd
#       alias value_end getValueEnd
#     end
#   end

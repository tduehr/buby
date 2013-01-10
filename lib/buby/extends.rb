class Buby
  module Implants
    module Proxy
      def implanted?
        true
      end
    end
  end
end

require 'buby/extends/jruby'
require 'buby/extends/buby_array_wrapper'
require 'buby/extends/http_request_response'
require 'buby/extends/scan_issue'
require 'buby/extends/context_menu'
require 'buby/extends/extension_helpers'

class Buby
  module Implants
    module Proxy
      def implanted?
        true
      end
    end
  end
end

require 'buby/implants/jruby'
require 'buby/implants/buby_array_wrapper'
require 'buby/implants/http_request_response'
require 'buby/implants/scan_issue'
require 'buby/implants/context_menu_invocation'
require 'buby/implants/extension_helpers'
require 'buby/implants/cookie'

class Buby
  # @todo document
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
require 'buby/implants/context_menu_invocation'
require 'buby/implants/cookie'
require 'buby/implants/extension_helpers'
require 'buby/implants/http_request_response'
require 'buby/implants/intercepted_proxy_message'
require 'buby/implants/intruder_attack'
require 'buby/implants/message_editor'
require 'buby/implants/message_editor_controller'
require 'buby/implants/parameter'
require 'buby/implants/request_info'
require 'buby/implants/response_info'
require 'buby/implants/scanner_insertion_point'
require 'buby/implants/scan_issue'
require 'buby/implants/scan_queue_item'
require 'buby/implants/temp_file'
require 'buby/implants/text_editor'

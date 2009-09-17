
module WatchScan
  def evt_http_message(tool_name, is_request, message_info)
    super(tool_name, is_request, message_info)
    if tool_name == 'scanner' 
      if is_request
        puts "#"*70, "# REQUEST: #{message_info.url.toString}", "#"*70
        puts message_info.req_str
        puts
      else
        puts "#"*70, "# RESPONSE: #{message_info.url.toString}", "#"*70
        puts message_info.rsp_str
        puts
      end
    end
  end

  def init_WatchScan
    puts "WatchScan module initialized"
  end
end

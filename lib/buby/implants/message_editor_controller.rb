class Buby
  module Implants
    # This interface is used by an +IMessageEditor+ to obtain details about the
    # currently displayed message. Extensions that create instances of Burp's
    # HTTP message editor can optionally provide an implementation of
    # +IMessageEditorController+, which the editor will invoke when it requires
    # further information about the current message (for example, to send it to
    # another Burp tool). Extensions that provide custom editor tabs via an
    # +IMessageEditorTabFactory+ will receive a reference to an
    # +IMessageEditorController+ object for each tab instance they generate,
    # which the tab can invoke if it requires further information about the
    # current message.
    #
    module MessageEditorController
      # This method is used to retrieve the HTTP request associated with the
      # current message (which may itself be a response).
      #
      # @return [String] The HTTP request associated with the current message.
      #
      def getRequest
        String.from_java_bytes __getRequest
      end

      # This method is used to retrieve the HTTP response associated with the
      # current message (which may itself be a request).
      #
      # @return [String] The HTTP response associated with the current message.
      #
      def getResponse
        String.from_java_bytes __getResponse
      end

      # Install ourselves into the current +IMessageEditorController+ java class
      # @param [IMessageEditorController] controller
      #
      # @todo __persistent__?
      def self.implant(controller)
        unless controller.implanted? || controller.nil?
          pp [:implanting, controller, controller.class] if 
          controller.class.class_exec(controller) do |controller|
            a_methods = %w{
              getRequest
              getResponse
            }
            a_methods.each do |meth|
              alias_method "__"+meth.to_s, meth
            end
            include Buby::Implants::MessageEditorController
            a_methods.each do |meth|
              java_class.ruby_names_for_java_method(meth).each do |ruby_meth|
                define_method ruby_meth, Buby::Implants::MessageEditorController.instance_method(meth)
              end
            end
            include Buby::Implants::Proxy
          end
        end
        controller
      end
    end
  end
end

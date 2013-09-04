class Buby
  module Implants
    # This interface is used to provide extensions with an instance of Burp's
    # HTTP message editor, for the extension to use in its own UI. Extensions
    # should call {Buby#createMessageEditor} to obtain an instance of this
    # interface.
    #
    module MessageEditor
      # This method is used to display an HTTP message in the editor.
      #
      # @param [Array<byte>, String] message The HTTP message to be displayed.
      # @param [Boolean] isRequest Flags whether the message is an HTTP request
      #   or response.
      # @return [void]
      #
      def setMessage(message, isRequest)
        message = message.to_java_bytes if message.respond_to? :to_java_bytes
        message = message.to_java :byte if message.kind_of? Array
        __setMessage(message, isRequest)
      end

      # This method is used to retrieve the currently displayed message, which
      # may have been modified by the user.
      #
      # @return [String] The currently displayed HTTP message.
      #
      def getMessage
        String.from_java_bytes __getMessage
      end

      # This method returns the data that is currently selected by the user.
      #
      # @return [String, nil] The data that is currently selected by the user,
      #   or +nil+ if no selection is made.
      #
      def getSelectedData
        ret = __getSelectedData
        ret ? String.from_java_bytes(ret) : ret
      end

      # Install ourselves into the current +IMessageEditor+ java class
      # @param [IMessageEditor] editor
      #
      def self.implant(editor)
        unless editor.implanted? || editor.nil?
          pp [:implanting, editor, editor.class] if $DEBUG
          editor.class.class_exec(editor) do |editor|
            a_methods = %w{
              setMessage
              getMessage
              getSelectedData
            }
            a_methods.each do |meth|
              alias_method "__"+meth.to_s, meth
            end
            include Buby::Implants::MessageEditor
            a_methods.each do |meth|
              java_class.ruby_names_for_java_method(meth).each do |ruby_meth|
                define_method ruby_meth, Buby::Implants::MessageEditor.instance_method(meth)
              end
            end
            include Buby::Implants::Proxy
          end
        end
        editor
      end

    end
  end
end

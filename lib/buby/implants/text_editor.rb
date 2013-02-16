class Buby
  module Implants
    # This interface is used to provide extensions with an instance of Burp's
    # raw text editor, for the extension to use in its own UI. Extensions should
    # call {Buby#createTextEditor} to obtain an instance of this interface.
    #
    module TextEditor
      # This method is used to retrieve the currently displayed text.
      #
      # @return [String] The currently displayed text.
      #
      def getText
        String.from_java_bytes __getText
      end

      # This method is used to obtain the currently selected text.
      #
      # @return [String, nil] The currently selected text, or +nil+ if the user
      #   has not made any selection.
      #
      def getSelectedText
        String.from_java_bytes __getSelectedText
      end

      # Install ourselves into the current +ITextEditor+ java class
      # @param [ITextEditor] editor
      #
      # @todo __persistent__?
      def self.implant(editor)
        unless editor.implanted? || editor.nil?
          pp [:implanting, editor, editor.class] if $DEBUG
          editor.class.class_exec(editor) do |editor|
            a_methods = %w{
              getText
              getSelectedText
            }
            a_methods.each do |meth|
              alias_method "__"+meth.to_s, meth
            end
            include Buby::Implants::TextEditor
            a_methods.each do |meth|
              java_class.ruby_names_for_java_method(meth).each do |ruby_meth|
                define_method ruby_meth, Buby::Implants::TextEditor.instance_method(meth)
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

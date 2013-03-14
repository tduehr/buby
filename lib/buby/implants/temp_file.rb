class Buby
  module Implants
    # This interface is used to hold details of a temporary file that has been
    # created via a call to {Buby#saveToTempFile}.
    # 
    module TempFile
      # This method is used to retrieve the contents of the buffer that was
      #   saved in the temporary file.
      #
      # @return [String] The contents of the buffer that was saved in the
      #   temporary file.
      #
      def getBuffer
        String.from_java_bytes __getBuffer
      end

      # Install ourselves into the current +ITempFile+ java class
      # @param [ITempFile] file
      #
      def self.implant(file)
        unless file.implanted? || file.nil?
          pp [:implanting, file, file.class] if $DEBUG
          file.class.class_exec(file) do |file|
            a_methods = %w{
              getBuffer
            }
            a_methods.each do |meth|
              alias_method "__"+meth.to_s, meth
            end
            include Buby::Implants::TempFile
            a_methods.each do |meth|
              java_class.ruby_names_for_java_method(meth).each do |ruby_meth|
                define_method ruby_meth, Buby::Implants::TempFile.instance_method(meth)
              end
            end
            include Buby::Implants::Proxy
          end
        end
        file
      end
    end
  end
end

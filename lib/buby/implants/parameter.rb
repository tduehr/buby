class Buby
  module Implants
    # This interface is used to hold details about an HTTP request parameter.
    # 
    module Parameter

      # This method is used to retrieve the start offset of the parameter name
      # within the HTTP request.
      #
      # @return [Fixnum, nil] The start offset of the parameter name within
      #   the HTTP request, or +nil+ if the parameter is not associated with a
      #   specific request.
      #
      def getNameStart
        ret = __getNameStart
        ret == -1 ? nil : ret
      end

      # This method is used to retrieve the end offset of the parameter name
      # within the HTTP request.
      #
      # @return [Fixnum, nil] The end offset of the parameter name within the
      #   HTTP request, or +nil+ if the parameter is not associated with a
      #   specific request.
      #
      def getNameEnd
        ret = __getNameEnd
        ret == -1 ? nil : ret
      end

      # This method is used to retrieve the start offset of the parameter
      # value within the HTTP request.
      #
      # @return [Fixnum, nil] The start offset of the parameter value within
      #   the HTTP request, or +nil+ if the parameter is not associated with a
      #   specific request.
      #
      def getValueStart
        ret = __getValueStart
        ret == -1 ? nil : ret
      end

      # This method is used to retrieve the end offset of the parameter value
      # within the HTTP request.
      #
      # @return [Fixnum, nil] The end offset of the parameter value within the
      #   HTTP request, or +nil+ if the parameter is not associated with a
      #   specific request.
      #
      def getValueEnd
        ret = __getValueEnd
        ret == -1 ? nil : ret
      end

      # Install ourselves into the current +IParameter+ java class
      # @param [IParameter] parameter
      #
      # @todo __persistent__?
      def self.implant(parameter)
        unless parameter.implanted? || parameter.nil?
          pp [:implanting, parameter, parameter.class] if $DEBUG
          parameter.class.class_exec(parameter) do |parameter|
            a_methods = %w{
              getNameStart
              getNameEnd
              getValueEnd
              getValueStart
            }
            a_methods.each do |meth|
              alias_method "__"+meth.to_s, meth
            end
            include Buby::Implants::Parameter
            a_methods.each do |meth|
              java_class.ruby_names_for_java_method(meth).each do |ruby_meth|
                define_method ruby_meth, Buby::Implants::Parameter.instance_method(meth)
              end
            end
            include Buby::Implants::Proxy
          end
        end
        parameter
      end
    end
  end
end

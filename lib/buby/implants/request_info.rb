require 'uri'

class Buby
  module Implants
    # This interface is used to retrieve key details about an HTTP request.
    # Extensions can obtain an +IRequestInfo+ object for a given request by
    # calling {Buby#analyzeRequest}.
    #
    module RequestInfo

      # This method is used to obtain the parameters contained in the request.
      #
      # @return [Array<IParameter>] The parameters contained in the request.
      #
      def getParameters
        __getParameters.tap{|parm| Buby::Implants::Parameter.implant parm.first}
      end

      
      # Install ourselves into the current +IRequestInfo+ java class
      # @param [IRequestInfo] info
      #
      def self.implant(info)
        unless info.implanted? || info.nil?
          pp [:implanting, info, info.class] if $DEBUG
          info.class.class_exec(info) do |info|
            a_methods = %w{
              getParameters
            }
            a_methods.each do |meth|
              alias_method "__"+meth.to_s, meth
            end
            include Buby::Implants::RequestInfo
            a_methods.each do |meth|
              java_class.ruby_names_for_java_method(meth).each do |ruby_meth|
                define_method ruby_meth, Buby::Implants::RequestInfo.instance_method(meth)
              end
            end
            include Buby::Implants::Proxy
          end
        end
        info
      end
      
    end
  end
end
class Buby
  module Implants
    # This interface is used to hold details about an Intruder attack.
    #
    module IntruderAttack
      # This method is used to retrieve the request template for the attack.
      #
      # @return [String] The request template for the attack.
      #
      def getRequestTemplate
        pp [:got_getRequestTemplate] if $DEBUG
        String.from_java_bytes __getRequestTemplate
      end

      # Install ourselves into the current +IIntruderAttack+ java class
      # @param [IIntruderAttack] intruder_attack
      #
      # @todo __persistent__?
      def self.implant(intruder_attack)
        unless intruder_attack.implanted? || intruder_attack.nil?
          pp [:implanting, intruder_attack, intruder_attack.class] if 
          intruder_attack.class.class_exec(intruder_attack) do |intruder_attack|
            a_methods = %w{
              getRequestTemplate
            }
            a_methods.each do |meth|
              alias_method "__"+meth.to_s, meth
            end
            include Buby::Implants::IntruderAttack
            a_methods.each do |meth|
              java_class.ruby_names_for_java_method(meth).each do |ruby_meth|
                define_method ruby_meth, Buby::Implants::IntruderAttack.instance_method(meth)
              end
            end
            include Buby::Implants::Proxy
          end
        end
        intruder_attack
      end
      
    end
  end
end
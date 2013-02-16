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
      # @param [IIntruderAttack] attack
      #
      # @todo __persistent__?
      def self.implant(attack)
        unless attack.implanted? || attack.nil?
          pp [:implanting, attack, attack.class] if $DEBUG
          attack.class.class_exec(attack) do |attack|
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
        attack
      end
      
    end
  end
end
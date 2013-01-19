class Buby
  module Parameter
    class Base
      include Java::Burp::IParameter
      attr_accessor :name, :value
      # @overload initialize
      #   Create an empty instance
      #   @param [void]
      # @overload initialize(hash)
      #   @param [Hash] hash name set to key, value set to value
      # @overload initialize(name, value)
      #   @param [String] name
      #   @param [String] value
      # @overload initialize(name, value, type)
      #   @param [String] name
      #   @param [String] value
      #   @param [Fixnum] type
      # 
      def initialize *args
        raise ArgumentError, "#{args.size} for 0..3" if args.size > 3
        case args.size
        when 0
        when 1
          hsh = args.first
          @name = hsh[:name] || hsh['name']
          @value = hsh[:value] || hsh['value']
        when 2, 3
          @name, @value, @type = args
        end
      end
      def getType; @type.to_i; end
      def getName; @name;   end
      def getValue; @value; end
      def getNameStart; -1; end
      def getNameEnd;   -1; end
      def getValueEnd;  -1; end
      def getValueStart;-1; end
    end
  end
end

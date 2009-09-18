
class Buby
  class BubyArrayWrapper
    include Enumerable

    attr_reader :array_obj

    def initialize(obj)
      @array_obj = obj
    end

    def [](*args)
      if args.size == 1 and args.first.kind_of? Numeric
        self.array_obj[args[0]]
      else
        self.to_a(*args)
      end
    end

    def each
      self.array_obj.size.times do |idx|
        yield self.array_obj[idx]
      end
    end

    def size
      self.array_obj.size
    end
    alias length size

    def first
      return(self.array_obj[0]) if(self.size > 0)
    end

    def last
      return self.array_obj[self.size - 1] if(self.size > 0)
    end

  end

end

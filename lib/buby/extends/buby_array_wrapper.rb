
class Buby
  class BubyArrayWrapper
    include Enumerable

    attr_reader :java_obj

    def initialize(obj)
      @java_obj = obj
    end

    def [](*args)
      if args.size == 1 and args.first.kind_of? Numeric
        self.java_obj[args[0]]
      else
        self.to_a(*args)
      end
    end

    def each
      self.java_obj.size.times do |idx|
        yield self.java_obj[idx]
      end
    end

    def size
      self.java_obj.size
    end
    alias length size

    def first
      return(self.java_obj[0]) if(self.size > 0)
    end

    def last
      return self.java_obj[self.size - 1] if(self.size > 0)
    end

  end

end

class Buby
  module ObjectImplants
    def java_proxy?
      false
    end

    def try(meth, *args, &block)
      __send__ meth, *args, &block if respond_to? meth
    end

    def implanted?
      false
    end
  end

  module EnumerableImplants
    # XXX backport for 1.8.7
    def each_with_object(memo)
      inject(memo) do |memo, obj|
        yield obj, memo
      end
    end
  end

  module JavaClassImplants
    def ruby_names_for_java_method meth
      self_java_ref = JRuby.reference(self).javaClass
      java_meth = self_java_ref.getMethod(meth)
      org.jruby.javasupport.JavaUtil.getRubyNamesForJavaName(java_meth.name, [java_meth])
    end

    private
    # copies wrapper_id method to java_id and all ruby-like aliases
    # used to re-attach java method proxies to new call wrapper
    #
    # @param java_id target java method (the original java method name)
    def rewrap_java_method java_id
      ruby_names_for_java_method(java_id).each do |ruby_name|
        alias_method(ruby_name, java_id) unless wrapper_id == ruby_name
      end
    end
  end
end

class Object
  include Buby::ObjectImplants
end

class Enumerable
  include Buby::EnumerableImplants unless [].respond_to?(:each_with_object)
end

module Java
  class JavaClass < Java::JavaObject
    include Buby::JavaClassImplants
  end
end


$:.unshift File.join(File.dirname(Dir.glob(File.join(File.dirname(Java::JavaLang::System.getProperties['java.class.path'].split(File::PATH_SEPARATOR).grep(/burp.*\.jar/).first),"bapps",'**','bubystart.rb')).first),"lib")

require 'buby/burp_extender'

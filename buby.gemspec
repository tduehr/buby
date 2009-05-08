# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name = %q{buby}
  s.version = "1.0.0"

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.authors = ["Eric Monti - Matasano Security"]
  s.date = %q{2009-05-08}
  s.default_executable = %q{buby}
  s.description = %q{Buby is a mashup of JRuby with the popular commercial web security testing tool Burp Suite from PortSwigger.  Burp is driven from and tied to JRuby with a Java extension using the BurpExtender API.  This extension aims to add Ruby scriptability to Burp Suite with an interface comparable to the Burp's pure Java extension interface.}
  s.email = %q{emonti@matasano.com}
  s.executables = ["buby"]
  s.extra_rdoc_files = ["History.txt", "README.rdoc", "bin/buby"]
  s.files = ["History.txt", "README.rdoc", "Rakefile", "bin/buby", "buby.gemspec", "java/buby.jar", "java/src/BurpExtender.class", "java/src/BurpExtender.java", "java/src/burp/IBurpExtender.class", "java/src/burp/IBurpExtender.java", "java/src/burp/IBurpExtenderCallbacks.class", "java/src/burp/IBurpExtenderCallbacks.java", "lib/buby.rb", "samples/basic.rb", "spec/buby_spec.rb", "spec/spec_helper.rb", "tasks/ann.rake", "tasks/bones.rake", "tasks/gem.rake", "tasks/git.rake", "tasks/notes.rake", "tasks/post_load.rake", "tasks/rdoc.rake", "tasks/rubyforge.rake", "tasks/setup.rb", "tasks/spec.rake", "tasks/svn.rake", "tasks/test.rake", "tasks/zentest.rake", "test/test_buby.rb"]
  s.has_rdoc = true
  s.homepage = %q{http://github.com/emonti/buby}
  s.rdoc_options = ["--main", "README.rdoc"]
  s.require_paths = ["lib", "java"]
  s.rubyforge_project = %q{buby}
  s.rubygems_version = %q{1.3.1}
  s.summary = %q{Buby is a mashup of JRuby with the popular commercial web security testing tool Burp Suite from PortSwigger}
  s.test_files = ["test/test_buby.rb"]

  if s.respond_to? :specification_version then
    current_version = Gem::Specification::CURRENT_SPECIFICATION_VERSION
    s.specification_version = 2

    if Gem::Version.new(Gem::RubyGemsVersion) >= Gem::Version.new('1.2.0') then
      s.add_development_dependency(%q<bones>, [">= 2.5.0"])
    else
      s.add_dependency(%q<bones>, [">= 2.5.0"])
    end
  else
    s.add_dependency(%q<bones>, [">= 2.5.0"])
  end
end

require 'rubygems'
require 'rake'
require 'rake/clean'

begin
  require 'jeweler'
  Jeweler::Tasks.new do |gem|
    gem.name = "buby"
    gem.summary = %q{Buby is a mashup of JRuby with the popular commercial web security testing tool Burp Suite from PortSwigger}
    gem.description = %q{Buby is a mashup of JRuby with the popular commercial web security testing tool Burp Suite from PortSwigger.  Burp is driven from and tied to JRuby with a Java extension using the BurpExtender API.  This extension aims to add Ruby scriptability to Burp Suite with an interface comparable to the Burp's pure Java extension interface.}
    gem.email = "emonti@matasano.com"
    gem.homepage = "http://emonti.github.com/buby"
    gem.authors = ["Eric Monti - Matasano Security"]
    gem.platform = "java"
    gem.test_files = ["test/buby_test.rb"]
    gem.require_paths << 'java'
    gem.rdoc_options = ["--main", "README.rdoc"]
    gem.extra_rdoc_files = ["History.txt", "README.rdoc", "bin/buby"]
  end
rescue LoadError
  puts "Jeweler (or a dependency) not available. Install it with: sudo gem install jeweler"
end

require 'rake/testtask'
Rake::TestTask.new(:test) do |test|
  test.libs << 'lib' << 'test' << 'java'
  test.pattern = 'test/**/*_test.rb'
  test.verbose = true
end

task :test => :check_dependencies

task :default => :test

require 'rake/rdoctask'
Rake::RDocTask.new do |rdoc|
  if File.exist?('VERSION')
    version = File.read('VERSION')
  else
    version = ""
  end

  rdoc.rdoc_dir = 'rdoc'
  rdoc.title = "buby #{version}"
  rdoc.rdoc_files.include('README*')
  rdoc.rdoc_files.include('History.txt')
  rdoc.rdoc_files.include('bin/buby')
  rdoc.rdoc_files.include('lib/**/*.rb')
end


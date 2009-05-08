# Look in the tasks/setup.rb file for the various options that can be
# configured in this Rakefile. The .rake files in the tasks directory
# are where the options are used.

begin
  require 'bones'
  Bones.setup
rescue LoadError
  begin
    load 'tasks/setup.rb'
  rescue LoadError
    raise RuntimeError, '### please install the "bones" gem ###'
  end
end

ensure_in_path 'lib'
ensure_in_path 'java'
require 'buby'

task :default => 'spec:run'

PROJ.name = 'buby'
PROJ.authors = 'Eric Monti - Matasano Security'
PROJ.email = 'emonti@matasano.com'
PROJ.url = 'http://github.com/emonti/buby'
PROJ.version = Buby::VERSION
PROJ.rubyforge.name = 'buby'
PROJ.readme_file = 'README.rdoc'
PROJ.libs << "java"

PROJ.spec.opts << '--color'

# EOF

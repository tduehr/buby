class BurpExtender
  # @api private
  class ConsolePane < Java::JavaxSwing::JScrollPane
    HEADER = " Welcome to the Burp JRuby IRB Console [#{JRUBY_VERSION} (#{RUBY_VERSION})]\n\n"
    attr_accessor :text, :tar
    def initialize
      super
      @text = Java::JavaxSwing::JTextPane.new
      @text.font = find_font('Monospaced', Java::JavaAwt::Font::PLAIN, 14, 'Anonymous Pro', 'Anonymous', 'Monaco', 'Andale Mono')
      @text.margin = Java::JavaAwt::Insets.new(8,8,8,8)
      @text.caret_color = Java::JavaAwt::Color.new(0xa40000)
      @text.background  = Java::JavaAwt::Color.new(0xf2f2f2)
      @text.foreground  = Java::JavaAwt::Color.new(0xa40000)
      self.viewport_view = @text
      @tar = begin
        Java::OrgJrubyDemo::TextAreaReadline.new(@text, HEADER)
      rescue NameError
        require 'readline'
        Java::OrgJrubyDemoReadline::TextAreaReadline.new(text, HEADER)
      end
        
      JRuby.objectspace = true # useful for code completion
      @tar.hook_into_runtime_with_streams(JRuby.runtime)
    end

    # Try to find preferred font family, use otherwise -- err --  otherwise
    def find_font(otherwise, style, size, *families)
      avail_families = Java::JavaAwt::GraphicsEnvironment.local_graphics_environment.available_font_family_names
      fontname = families.find(proc {otherwise}) { |name| avail_families.include? name }
      Java::JavaAwt::Font.new(fontname, style, size)
    end
  end
end

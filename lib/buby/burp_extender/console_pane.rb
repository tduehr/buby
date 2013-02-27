class BurpExtender
  class ConsolePane < Java::JavaxSwing::JScrollPane
    attr_accessor :text, :tar
    def initialize
      super
      @text = javax.swing.JTextPane.new
      @text.font = find_font('Monospaced', java.awt.Font::PLAIN, 14, 'Anonymous Pro', 'Anonymous', 'Monaco', 'Andale Mono')
      @text.margin = java.awt.Insets.new(8,8,8,8)
      @text.caret_color = java.awt.Color.new(0xa40000)
      @text.background  = java.awt.Color.new(0xf2f2f2)
      @text.foreground  = java.awt.Color.new(0xa40000)
      self.viewport_view = @text
      @tar = org.jruby.demo.TextAreaReadline.new(@text, " Welcome to the Burp JRuby IRB Console [#{JRUBY_VERSION} (#{RUBY_VERSION})]\n\n")
      JRuby.objectspace = true # useful for code completion
      @tar.hook_into_runtime_with_streams(JRuby.runtime)
    end

    # Try to find preferred font family, use otherwise -- err --  otherwise
    def find_font(otherwise, style, size, *families)
      avail_families = java.awt.GraphicsEnvironment.local_graphics_environment.available_font_family_names
      fontname = families.find(proc {otherwise}) { |name| avail_families.include? name }
      java.awt.Font.new(fontname, style, size)
    end
  end
end
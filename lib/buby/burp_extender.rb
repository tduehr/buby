require 'buby'
require 'buby/extender'
require 'pp'
require 'buby/burp_extender/context_menu_factory'

if ARGV.empty?
  # default options, esp. useful for jrubyw
  ARGV << '--readline' << '--prompt' << 'inf-ruby'
end

# This is the default JRuby implementation of IBurpExtender for use as a JRuby
# extension.
#
class BurpExtender
  include Buby::Extender
  include Java::Burp::ITab
  include Java::Burp::IBurpExtender

  @@handler = Buby.new

  # ExtensionHelpers for internal reference
  attr_reader :helpers
  # BurpExtenderCallbacks for internal reference.
  attr_reader :callbacks
  # Start with an interactive session running. Defaults to IRB when +nil+ or unkown, can be +irb+, +none+ or +pry+.
  attr_accessor :interactive
  # Set $DEBUG on start.
  attr_accessor :debug
  # Run interactive session in a window
  attr_accessor :windowed
  # Allow proxy interception on load.
  attr_accessor :intercept
  # Unload the extension when exiting irb. Defaults to nil. The values +exit+
  #   and +unload+ will close Burp and unload Buby, respectively.
  attr_accessor :on_quit

  # save the current BurpExtender settings to the preferences cache
  def save_settings!
    @callbacks.saveExtensionSetting('intercept', @intercept ? @intercept.to_s : nil)
    case @interactive
    when nil, 'irb', 'pry', 'none'
      @callbacks.saveExtensionSetting('interactive', @interactive)
    when false
      @callbacks.saveExtensionSetting('interactive', 'none')
    else
      @callbacks.saveExtensionSetting('interactive', @interactive.to_s)
    end
    @callbacks.saveExtensionSetting('debug', @debug ? @debug.to_s : nil)
    @callbacks.saveExtensionSetting('windowed', @windowed ? @windowed.to_s : nil)
    case @on_quit
    when 'exit', 'quit', nil
      @callbacks.saveExtensionSetting('on_quit', @on_quit)
    else
      @callbacks.saveExtensionSetting('on_quit', @on_quit.to_s)
    end
  end

  # @group Internals
  # @see Buby::Extender#registerExtenderCallbacks
  def registerExtenderCallbacks(callbacks)
    puts @@handler.methods.inspect
    @@handler.extender_initialize self
    @callbacks = callbacks
    @helpers = @callbacks.helpers
    @callbacks.setExtensionName("Buby")

    @intercept = @callbacks.loadExtensionSetting('intercept')
    @interactive = @callbacks.loadExtensionSetting('interactive')
    @debug = true || @callbacks.loadExtensionSetting('debug')
    @windowed = @callbacks.loadExtensionSetting('windowed')
    @on_quit = @callbacks.loadExtensionSetting('on_quit')

    $DEBUG = 1 if @debug
    @callbacks.setProxyInterceptionEnabled false unless @intercept

    require 'buby'
    unless @interactive == 'none'
      require 'buby/burp_extender/console_pane'
      @pane = ConsolePane.new

      @callbacks.customizeUiComponent @pane
      if @windowed
        @frame = javax.swing.JFrame.new("Buby #{@interactive || 'IRB'} Console (tab will autocomplete)")
        @frame.set_size(700, 600)
        @frame.content_pane.add(@pane)
        java.awt.EventQueue.invoke_later {
          @frame.visible = true
        }
        @callbacks.customizeUiComponent @frame
      else
        require 'buby/burp_extender/console_tab'
        @tab = BurpExtender::ConsoleTab.new @pane
        @callbacks.addSuiteTab self
      end
    end

    $burp = @@handler

    super

    @callbacks.registerContextMenuFactory ContextMenuFactory.new(self)
    @callbacks.getStderr.flush
    case @interactive
    when 'irb', nil
      start_irb
    when 'pry'
      start_pry
    when 'none'
    else
      @callbacks.getStderr.write "Unknown interactive setting #{@interactive.dump}. Starting IRB".to_java_bytes
      start_irb
    end
  end

  def move_to_tab
    if @windowed
      java.awt.EventQueue.invoke_later {
        @frame.visible = false
      }
      @callbacks.addSuiteTab self
      @windowed = false
    end
  end

  def move_to_window
    unless @windowed
      @frame = javax.swing.JFrame.new('JRuby IRB Console (tab will autocomplete)')
      @frame.set_size(700, 600)
      @frame.content_pane.add(@pane)

      java.awt.EventQueue.invoke_later {
        @frame.visible = true
      }
      @callbacks.removeSuiteTab self
      @windowed = true
    end
  end

  # Starts an IRB Session
  def start_irb
    require 'irb'
    require 'irb/completion'

    @interactive_running = true
    puts "Starting IRB: Global $burp is set to #{$burp.inspect}"
    IRB.start(__FILE__)
    @interactive_running = false
    quitting
  end

  def start_pry
    require 'pry'

    @interactive_running = true
    puts "Starting Pry: Global $burp is set to #{$burp.inspect}"
    Pry.start
    @interactive_running = false
    quitting
  end

  def quitting
    case @on_quit
    when 'exit'
      @callbacks.exitSuite
    when 'unload'
      @callbacks.unloadExtension
    else
      if @frame
        java.awt.EventQueue.invoke_later {
          @frame.dispose
          @frame = nil
        }
      else
        @callbacks.removeSuiteTab self
      end
    end
  end

  def extensionUnloaded
    if @frame
      java.awt.EventQueue.invoke_later {
        @frame.dispose
        @frame = nil
      }
    end
    
    super
  end

  # @group Tab
  def getUiComponent
    @pane
  end

  def getTabCaption
    "Buby v#{Buby::Version::STRING}"
  end

  # Try to find preferred font family, use otherwise -- err --  otherwise
  def find_font(otherwise, style, size, *families)
    avail_families = java.awt.GraphicsEnvironment.local_graphics_environment.available_font_family_names
    fontname = families.find(proc {otherwise}) { |name| avail_families.include? name }
    java.awt.Font.new(fontname, style, size)
  end
end

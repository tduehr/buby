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
  include Java::Burp::IBurpExtender

  @@handler ||= Buby.new

  # ExtensionHelpers for internal reference
  attr_reader :helpers
  # BurpExtenderCallbacks for internal reference.
  attr_reader :callbacks
  # Start with an interactive session running. Defaults to IRB when +nil+ or unkown, can be +irb+, +none+ or +pry+.
  attr_accessor :interactive
  # Set $DEBUG on start.
  attr_accessor :debug
  # Run interactive session in a window instead of a tab.
  attr_accessor :windowed
  # Allow proxy interception on load.
  attr_accessor :intercept
  # Unload the extension when exiting irb. Defaults to nil. The values +exit+
  #   and +unload+ will close Burp and unload Buby, respectively.
  attr_accessor :on_quit

  attr_accessor :frame

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
    when 'exit', 'unload', nil
      @callbacks.saveExtensionSetting('on_quit', @on_quit)
    else
      @callbacks.saveExtensionSetting('on_quit', @on_quit.to_s)
    end
  end

  # @group Internals
  # @see Buby::Extender#registerExtenderCallbacks
  def registerExtenderCallbacks(callbacks)
    @@handler.extender_initialize self
    @callbacks = callbacks
    @helpers = @callbacks.helpers
    @callbacks.setExtensionName("Buby")

    sys_properties = Java::JavaLang::System.getProperties

    @intercept = sys_properties.getProperty("burp.buby.intercept", nil) || @callbacks.loadExtensionSetting('intercept')
    @interactive = sys_properties.getProperty("burp.buby.interactive", nil) || @callbacks.loadExtensionSetting('interactive') || 'irb'
    @debug = sys_properties.getProperty("burp.buby.debug", nil) || @callbacks.loadExtensionSetting('debug')
    @windowed = sys_properties.getProperty("burp.buby.windowed", nil) || @callbacks.loadExtensionSetting('windowed') || 'false'
    @on_quit = sys_properties.getProperty("burp.buby.on_quit", nil) || @callbacks.loadExtensionSetting('on_quit') || 'unload'

    $DEBUG = @debug unless @debug && @debug.match(/\Afalse\Z/i)
    @callbacks.setProxyInterceptionEnabled false unless @intercept &&  @intercept.match(/\A(?:false|f|n|no|off)\Z/i)

    init_console unless @interactive == 'none'

    $burp = @@handler

    super

    @main_menu = Java::JavaAwt::Frame.getFrames.map{|x| x.getMenuBar }.compact.find_all do |mb|
      labels = mb.getMenuCount.times.map{|x| mb.getMenu(x).label}
      !(labels & ["Burp", "Intruder", "Repeater", "Window", "Help"]).empty?
    end.first

    if @main_menu # awt based laf
      require 'buby/burp_extender/menu_item'
      require 'buby/burp_extender/menu'
      @menu = BurpExtender::Menu.new self
      @menu.add(BurpExtender::MenuItem.new('Toggle console mode', self) do |event|
        burp = event.source.burp
        burp.toggle_windowed
      end)
      pref_menu = BurpExtender::Menu.new self, "Preferences.."
    else
      # swing based laf ... isn't Java ...great...

      require 'buby/burp_extender/jmenu_item'
      require 'buby/burp_extender/jmenu'

      @main_menu = Java::JavaAwt::Frame.getFrames.map{|x| x.getJMenuBar if x.respond_to?(:getJMenuBar)}.compact.find_all do |mb|
        labels = mb.getMenuCount.times.map{|x| mb.getMenu(x).label}
        !(labels & ["Burp", "Intruder", "Repeater", "Window", "Help"]).empty?
      end.first

      @menu = BurpExtender::JMenu.new self
      @menu.add(BurpExtender::JMenuItem.new('Toggle console mode', self) do |event|
        burp = event.source.burp
        burp.toggle_windowed
      end)
      pref_menu = BurpExtender::JMenu.new self, "Preferences.."
    end

    @main_menu.add @menu

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

  def toggle_windowed
    if @frame
      move_to_tab
    else
      move_to_window
    end
  end

  def move_to_tab
    require 'buby/burp_extender/console_tab'
    @tab = BurpExtender::ConsoleTab.new @pane
    @callbacks.addSuiteTab @tab
    if @frame
      Java::JavaAwt::EventQueue.invoke_later {
        @frame.dispose if @frame
        @frame = nil
      }
    end
  end

  def move_to_window
    @callbacks.removeSuiteTab @tab if @tab
    create_frame
  end

  # Starts an IRB Session
  def start_irb
    require 'irb'
    require 'irb/completion'

    unless @interactive_running
      @interactive_running = true
      puts "Starting IRB: Global $burp is set to #{$burp.inspect}"
      IRB.start(__FILE__)
      quitting
    end
  end

  def start_pry
    require 'pry'

    unless @interactive_running
      @interactive_running = true
      puts "Starting Pry: Global $burp is set to #{$burp.inspect}"
      ENV['TERM'] = 'dumb'
      Pry.color = false

      # Pry makes a bunch of invalid assumptions. This seems to be the best we can do for now.
      Pry.toplevel_binding.pry
      quitting
    end
  end

  def quitting
    @interactive_running = false

    case @on_quit
    when 'exit'
      @callbacks.exitSuite
    when 'unload'
      @callbacks.unloadExtension
    else
      unload_ui
    end
  end

  def extensionUnloaded
    super
    unload_ui
  end

  private
  def unload_ui
    if @frame
      Java::JavaAwt::EventQueue.invoke_later {
        @frame.dispose if @frame
        @frame = nil
      }
    end

    @main_menu.remove @menu
    @callbacks.removeSuiteTab @tab if @tab
    @pane = nil
  end

  def init_console
    require 'buby/burp_extender/console_pane'
    @pane = ConsolePane.new

    @callbacks.customizeUiComponent @pane
    if @windowed
      create_frame
    else
      require 'buby/burp_extender/console_tab'
      @tab = BurpExtender::ConsoleTab.new @pane
      @callbacks.addSuiteTab @tab
    end
  end

  def create_frame
    require 'buby/burp_extender/console_frame'
    unless @frame
      @frame = BurpExtender::ConsoleFrame.new self, @pane do |event|
        @frame = nil if event.getID == Java::JavaAwtEvent::WindowEvent::WINDOW_CLOSED
      end
    end
  end
end

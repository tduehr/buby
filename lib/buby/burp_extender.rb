require 'buby'
require 'buby/extender'
require 'pp'
require 'buby/burp_extender/context_menu_factory'
require 'buby/burp_extender/jmenu_item'
require 'buby/burp_extender/jmenu'
require 'buby/burp_extender/jcheck_box_menu_item'


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
  attr_accessor :pane

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
    @interactive_sessions = 0
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

    $burp = @@handler

    super

    @main_menu = Java::JavaAwt::Frame.getFrames.map{|x| x.getJMenuBar if x.respond_to?(:getJMenuBar)}.compact.find_all do |mb|
      labels = mb.getMenuCount.times.map{|x| mb.getMenu(x).label}
      !(labels & ["Burp", "Intruder", "Repeater", "Window", "Help"]).empty?
    end.first

    @menu = BurpExtender::JMenu.new self
    @menu.add(tcm = BurpExtender::JMenuItem.new('Toggle console mode', self) do |event|
      self.toggle_windowed
    end)

    pref_menu = BurpExtender::JMenu.new self, "Preferences.."

    interact = BurpExtender::JMenu.new self, "Interactive..."

    mode_group = Java::JavaxSwing::ButtonGroup.new

    mode = BurpExtender::JMenu.new self, "Mode"
    %w{irb pry none}.each do |md|
      mode_item = Java::JavaxSwing::JRadioButtonMenuItem.new md
      mode_item.action_command = md
      # mode_item.selected = (@interactive == md)
      mode_item.addActionListener do |event|
        @callbacks.saveExtensionSetting('interactive', event.action_command)
        @interactive = event.action_command
      end
      mode_group.add mode_item
      mode.add mode_item
    end
    interact.add mode

    quit_group = Java::JavaxSwing::ButtonGroup.new

    oq = BurpExtender::JMenu.new self, "On quit"
    %w{exit unload none}.each do |md|
      menu_item = Java::JavaxSwing::JRadioButtonMenuItem.new md
      menu_item.action_command = md
      # menu_item.selected = (@on_quit == md)
      menu_item.addActionListener do |event|
        @callbacks.saveExtensionSetting('on_quit', event.action_command)
        @on_quit = event.action_command
      end
      quit_group.add menu_item
      oq.add menu_item
    end
    interact.add oq

    windowd = BurpExtender::JCheckBoxMenuItem.new(self, "Windowed", (@windowed && (@windowed != 'false'))) do |event|
      enabl = event.source.state

      @windowed = enabl
      if enabl
        @callbacks.saveExtensionSetting('windowed', 'true')
        self.move_to_window
      else
        @callbacks.saveExtensionSetting('windowed', nil)
        self.move_to_tab
      end
    end

    interact.add windowd
    pref_menu.add interact

    dbg = BurpExtender::JCheckBoxMenuItem.new self, "$DEBUG"  do |event|
      enabl = event.source.state
      @debug = enabl
      @callbacks.saveExtensionSetting('debug', enabl ? 'true' : nil)
      $DEBUG = enabl ? 1 : nil
    end

    interc = BurpExtender::JCheckBoxMenuItem.new self, "Disable intercept on start"  do |event|
      enabl = event.source.state
      if enabl
        @intercept = nil
        @callbacks.saveExtensionSetting('intercept', nil)
      else
        @intercept = true
        @callbacks.saveExtensionSetting('intercept', 'true')
      end
    end
    pref_menu.add interc

    dbg.state = !!$DEBUG
    pref_menu.add dbg

    @menu.add pref_menu

    @main_menu.add @menu

    @menu.addChangeListener do |event|
      if @menu.isSelected
        mode.getMenuComponents.each do |menu|
          menu.selected = (@interactive == menu.action_command)
        end

        oq.getMenuComponents.each do |menu|
          menu.selected = (@on_quit == menu.action_command)
        end

        if @frame
          tcm.text = 'Move console to tab'
        elsif @interactive_running
          tcm.text = 'Move console to window'
        else
          tcm.text = 'Start interactive session'
        end

        dbg.state = !!(@debug && (@debug != 'false'))
        interc.state = !(@intercept && (@intercept != 'false'))
        windowd.state = !!(@windowed && (@windowed != 'false'))
      end
    end

    @callbacks.getStderr.flush
    @callbacks.getStdout.flush
    start_interactive  unless @interactive == 'none'
  end

  def start_interactive(allow_multiple = false)
    unless @interactive_sessions.nonzero? || allow_multiple
      init_console
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
  end

  def toggle_windowed
    if @frame
      move_to_tab
    elsif @interactive_running
      move_to_window
    else
      start_interactive
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
      @interactive_sessions += 1
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
      @callbacks.exitSuite true
      unload_ui # just in case closing is cancelled, we need to kill the frame and tab
    when 'unload'
      @callbacks.unloadExtension
    else
      unload_ui
    end
  end

  def extensionUnloaded
    super
    unload_ui
    unload_menu
  end

  def inspect
    "<#{self.class}:0x#{self.hash.to_s(16)} @interactive=#{@interactive.inspect}, @windowed=#{@windowed.inspect}, @on_quit=#{@on_quit.inspect}, @intercept=#{@intercept.inspect}, @debug=#{@debug.inspect}, @callbacks=#{@callbacks.inspect}, @helpers=#{@helpers.inspect}>"
  end

  private
  def unload_ui
    if @frame
      Java::JavaAwt::EventQueue.invoke_later {
        @frame.dispose if @frame
        @frame = nil
      }
    end
  end

  def unload_menu
    @main_menu.remove @menu
    @callbacks.removeSuiteTab @tab if @tab
    @pane = nil
  end

  def init_console
    require 'buby/burp_extender/console_pane'
    @pane = ConsolePane.new

    @callbacks.customizeUiComponent @pane
    if @windowed && @windowed != 'false'
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

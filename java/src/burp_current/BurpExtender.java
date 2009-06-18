//import javax.annotation.PostConstruct; 

import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;

import org.jruby.*;
import org.jruby.javasupport.JavaUtil;
import org.jruby.runtime.ThreadContext; 
import org.jruby.runtime.builtin.IRubyObject; 

/**
 * This is an implementation of the BurpExtender/IBurpExtender interface
 * for Burp Suite which provides glue between a Ruby runtime and Burp.
 *
 * This is a complete implementation of the Burp Extender interfaces available
 * as of Burp Suite 1.2/1.2.05
 */
public class BurpExtender implements IBurpExtender { 
    public final static String INIT_METH =      "evt_extender_init";
    public final static String PROXYMSG_METH =  "evt_proxy_message";
    public final static String HTTPMSG_METH =   "evt_http_message";
    public final static String SCANISSUE_METH = "evt_scan_issue";
    public final static String MAINARGS_METH =  "evt_commandline_args";
    public final static String REG_METH =       "evt_register_callbacks";
    public final static String CLOSE_METH =     "evt_application_closing";

    // Internal reference to hold the ruby Burp handler
    private static IRubyObject r_obj = null;

    /**
     * Sets an internal reference to the ruby handler class or module to use 
     * for proxied BurpExtender events into a ruby runtime.
     *
     * Generally, this should probably be called before burp.StartBurp.main. 
     * However, it is also possible to set this afterwards and even swap in 
     * new objects during runtime.
     */
    public static void set_handler(IRubyObject hnd) { r_obj = hnd; }

    /** 
     * Returns the internal Ruby handler reference. 
     *
     * The handler is the ruby class or module used for proxying BurpExtender 
     * events into a ruby runtime.
     */
    public static IRubyObject get_handler() { return r_obj; }


    /** 
     * This constructor is invoked from Burp's extender framework.
     *
     * This implementation invokes the <code>INIT_METH</code> method
     * from the Ruby handler object if one is defined passing it Ruby
     * usable reference to the instance.
     *
     */
    public BurpExtender() {
      if (r_obj !=null && r_obj.respondsTo(INIT_METH))
        r_obj.callMethod(ctx(r_obj), INIT_METH, to_ruby(rt(r_obj), this));
    }


    /**
     * This method is invoked immediately after the implementation's constructor
     * to pass any command-line arguments that were passed to Burp Suite on
     * startup. 
     *
     * This implementation invokes the method defined by 
     * <code>MAINARGS_METH</code> in the Ruby handler if both the handler
     * and its ruby method are defined.
     *
     * It allows Ruby implementations to control aspects of their behaviour at 
     * runtime by defining their own command-line arguments.
     *
     * WARNING: Burp appears to have a bug (as of 1.2 and 1.2.05) which causes
     * Burp to exit immediately if arguments are supplied regardless whether 
     * this handler is used.
     *
     * @param args The command-line arguments passed to Burp Suite on startup.
     */
    public void setCommandLineArgs(String[] args) {
      if(r_obj != null && r_obj.respondsTo(MAINARGS_METH))
        r_obj.callMethod(ctx(r_obj), MAINARGS_METH, to_ruby(rt(r_obj), args));
    }
  
    /**
     * This method is invoked on startup. It registers an instance of the 
     * <code>burp.IBurpExtenderCallbacks</code> interface, providing methods 
     * that may be invoked by the implementation to perform various actions.
     * 
     * The call to registerExtenderCallbacks need not return, and 
     * implementations may use the invoking thread for any purpose.<p>
     *
     * This implementation simply passes a ruby-usable "callbacks" instance to 
     * the Ruby handler using the method defined by <code>REG_METH</code> if 
     * both the handler and its ruby method are defined.
     *
     * @param callbacks An implementation of the 
     * <code>IBurpExtenderCallbacks</code> interface.
     */
    public void registerExtenderCallbacks(IBurpExtenderCallbacks cb) {
      if(r_obj != null && r_obj.respondsTo(REG_METH)) {
        cb.issueAlert("[BurpExtender] registering JRuby handler callbacks");
        r_obj.callMethod(ctx(r_obj), REG_METH, to_ruby(rt(r_obj), cb));
      }
    }

    /**
     * This method is invoked by Burp Proxy whenever a client request or server
     * response is received. 
     *
     * This implementation simply passes all arguments to the Ruby handler's 
     * method defined by <code>PROXYMSG_METH</code> if both the handler and
     * its ruby method are defined.
     *
     * This allows Ruby implementations to perform logging functions, modify 
     * the message, specify an action (intercept, drop, etc.) and perform any 
     * other arbitrary processing.
     *
     * @param messageReference An identifier which is unique to a single 
     * request/response pair. This can be used to correlate details of requests
     * and responses and perform processing on the response message accordingly.
     * @param messageIsRequest Flags whether the message is a client request or
     * a server response.
     * @param remoteHost The hostname of the remote HTTP server.
     * @param remotePort The port of the remote HTTP server.
     * @param serviceIsHttps Flags whether the protocol is HTTPS or HTTP.
     * @param httpMethod The method verb used in the client request.
     * @param url The requested URL.
     * @param resourceType The filetype of the requested resource, or a 
     * zero-length string if the resource has no filetype.
     * @param statusCode The HTTP status code returned by the server. This value
     * is <code>null</code> for request messages.
     * @param responseContentType The content-type string returned by the 
     * server. This value is <code>null</code> for request messages.
     * @param message The full HTTP message.
     * @param action An array containing a single integer, allowing the
     * implementation to communicate back to Burp Proxy a non-default 
     * interception action for the message. The default value is 
     * <code>ACTION_FOLLOW_RULES</code>. Set <code>action[0]</code> to one of 
     * the other possible values to perform a different action.
     * @return Implementations should return either (a) the same object received
     * in the <code>message</code> paramater, or (b) a different object 
     * containing a modified message.
     */
    public byte[] processProxyMessage( 
        int messageReference, 
        boolean messageIsRequest, 
        String remoteHost, 
        int remotePort, 
        boolean serviceIsHttps, 
        String httpMethod, 
        String url, 
        String resourceType, 
        String statusCode, 
        String responseContentType, 
        byte[] message, 
        int[] action ) 
    {

      if (r_obj != null && r_obj.respondsTo(PROXYMSG_METH)) {
        Ruby rt = rt(r_obj);
        // prepare an alternate action value to present to ruby
        IRubyObject r_action = to_ruby(rt, action);

        // prepare an alternate message value to present to ruby
        IRubyObject r_msg = to_ruby(rt, RubyString.bytesToString(message));

        IRubyObject pxy_msg[] = {
          to_ruby(rt, messageReference),
          to_ruby(rt, messageIsRequest),
          to_ruby(rt, remoteHost),
          to_ruby(rt, remotePort),
          to_ruby(rt, serviceIsHttps),
          to_ruby(rt, httpMethod),
          to_ruby(rt, url),
          to_ruby(rt, resourceType),
          to_ruby(rt, statusCode),
          to_ruby(rt, responseContentType),
          r_msg,
          r_action
        };

        // slurp back in the action value in-case it's been changed
        action[0] = ((int[]) JavaUtil.convertRubyToJava(r_action))[0];

        IRubyObject ret = r_obj.callMethod(ctx(r_obj), PROXYMSG_METH, pxy_msg);
        if(ret != r_msg)
          return ((RubyString) ret).getBytes();
      }

      return message;
    }

    /** 
     * Added in Burp 1.2.09 
     * No javadoc yet but here's what the PortSwigger dev blog has to say:
     *
     * The processHttpMessage method is invoked whenever any of Burp's tools 
     * makes an HTTP request or receives a response. This is effectively a 
     * generalised version of the existing processProxyMessage method, and 
     * can be used to intercept and modify the HTTP traffic of all Burp 
     * tools.
     */
    public void processHttpMessage(
        String toolName, 
        boolean messageIsRequest, 
        IHttpRequestResponse messageInfo ) 
    {
      if (r_obj != null && r_obj.respondsTo(HTTPMSG_METH)) {
        Ruby rt = rt(r_obj);
        IRubyObject http_msg[] = {
          to_ruby(rt, toolName),
          to_ruby(rt, messageIsRequest),
          to_ruby(rt, messageInfo)
        };

        r_obj.callMethod(ctx(r_obj), HTTPMSG_METH, http_msg);
      }
    }

    /** 
     * Added in Burp 1.2.09 
     *
     * The newScanIssue method is invoked whenever Burp Scanner discovers a 
     * new, unique issue, and can be used to perform customised reporting or 
     * logging of issues.
     */
    public void newScanIssue(IScanIssue issue) {
      if (r_obj != null && r_obj.respondsTo(SCANISSUE_METH))
        r_obj.callMethod(ctx(r_obj), SCANISSUE_METH, to_ruby(rt(r_obj), issue));
    }


    /**
     * This method is invoked immediately before Burp Suite exits. 
     * This implementation simply invokes the Ruby handler's method defined
     * by <code>CLOSE_METH</code> if both the handler and its ruby method are
     * defined.
     *
     * This allows implementations to carry out any clean-up actions necessary
     * (e.g. flushing log files or closing database resources, etc.).
     */
    public void applicationClosing() {
      if (r_obj != null && r_obj.respondsTo(CLOSE_METH))
        r_obj.callMethod(ctx(r_obj), CLOSE_METH);
    }

    // Private method to return the ThreadContext for a given ruby object.
    // This is used in the various event proxies
    private ThreadContext ctx(IRubyObject obj) {
      return rt(obj).getThreadService().getCurrentContext();
    }

    // Private method to return the ruby runtime for a given ruby object.
    // This is used in the various event proxies
    private Ruby rt(IRubyObject obj) {
      return obj.getRuntime();
    }

    // private method to transfer arbitrary java objects into a ruby runtime.
    // This is used in the various event proxies to pass arguments to the
    // ruby handler object.
    private IRubyObject to_ruby(Ruby rt, Object obj) {
      return JavaUtil.convertJavaToUsableRubyObject(rt, obj);
    }

    /** 
     * Causes Burp Proxy to follow the current interception rules to determine
     * the appropriate action to take for the message.
     */
    public final static int ACTION_FOLLOW_RULES = 0;

    /** 
     * Causes Burp Proxy to present the message to the user for manual
     * review or modification.
     */
    public final static int ACTION_DO_INTERCEPT = 1;

    /** 
     * Causes Burp Proxy to forward the message to the remote server or client.
     */
    public final static int ACTION_DONT_INTERCEPT = 2;

    /** 
     * Causes Burp Proxy to drop the message and close the client connection.
     */
    public final static int ACTION_DROP = 3;    

}


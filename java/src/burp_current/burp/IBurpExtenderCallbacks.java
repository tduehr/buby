// Decompiled by Jad v1.5.8g. Copyright 2001 Pavel Kouznetsov.
// Jad home page: http://www.kpdus.com/jad.html
// Decompiler options: packimports(3) 

package burp;

import java.io.File;
import java.net.URL;

// Referenced classes of package burp:
//            IScanQueueItem, IHttpRequestResponse

public interface IBurpExtenderCallbacks
{

    public abstract byte[] makeHttpRequest(String s, int i, boolean flag, byte abyte0[])
        throws Exception;

    public abstract void sendToRepeater(String s, int i, boolean flag, byte abyte0[], String s1)
        throws Exception;

    public abstract void sendToIntruder(String s, int i, boolean flag, byte abyte0[])
        throws Exception;

    public abstract void sendToSpider(URL url)
        throws Exception;

    public abstract IScanQueueItem doActiveScan(String s, int i, boolean flag, byte abyte0[])
        throws Exception;

    public abstract void doPassiveScan(String s, int i, boolean flag, byte abyte0[], byte abyte1[])
        throws Exception;

    public abstract boolean isInScope(URL url)
        throws Exception;

    public abstract void includeInScope(URL url)
        throws Exception;

    public abstract void excludeFromScope(URL url)
        throws Exception;

    public abstract void issueAlert(String s);

    public abstract IHttpRequestResponse[] getProxyHistory();

    public abstract IHttpRequestResponse[] getSiteMap(String s);

    public abstract void restoreState(File file)
        throws Exception;

    public abstract void saveState(File file)
        throws Exception;

    public abstract String[][] getParameters(byte abyte0[])
        throws Exception;

    public abstract String[] getHeaders(byte abyte0[])
        throws Exception;
}

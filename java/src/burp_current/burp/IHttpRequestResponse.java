// Decompiled by Jad v1.5.8g. Copyright 2001 Pavel Kouznetsov.
// Jad home page: http://www.kpdus.com/jad.html
// Decompiler options: packimports(3) 

package burp;

import java.net.URL;

public interface IHttpRequestResponse
{

    public abstract String getHost();

    public abstract int getPort();

    public abstract String getProtocol();

    public abstract void setHost(String s)
        throws Exception;

    public abstract void setPort(int i)
        throws Exception;

    public abstract void setProtocol(String s)
        throws Exception;

    public abstract byte[] getRequest()
        throws Exception;

    public abstract URL getUrl()
        throws Exception;

    public abstract void setRequest(byte abyte0[])
        throws Exception;

    public abstract byte[] getResponse()
        throws Exception;

    public abstract void setResponse(byte abyte0[])
        throws Exception;

    public abstract short getStatusCode()
        throws Exception;
}

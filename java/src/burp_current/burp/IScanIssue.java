// Decompiled by Jad v1.5.8g. Copyright 2001 Pavel Kouznetsov.
// Jad home page: http://www.kpdus.com/jad.html
// Decompiler options: packimports(3) 

package burp;

import java.net.URL;

// Referenced classes of package burp:
//            IHttpRequestResponse

public interface IScanIssue
{

    public abstract String getHost();

    public abstract int getPort();

    public abstract String getProtocol();

    public abstract URL getUrl();

    public abstract String getIssueName();

    public abstract String getSeverity();

    public abstract String getConfidence();

    public abstract String getIssueBackground();

    public abstract String getRemediationBackground();

    public abstract String getIssueDetail();

    public abstract String getRemediationDetail();

    public abstract IHttpRequestResponse[] getHttpMessages();
}

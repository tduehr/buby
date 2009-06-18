// Decompiled by Jad v1.5.8g. Copyright 2001 Pavel Kouznetsov.
// Jad home page: http://www.kpdus.com/jad.html
// Decompiler options: packimports(3) 

package burp;


// Referenced classes of package burp:
//            IScanIssue

public interface IScanQueueItem
{

    public abstract String getStatus();

    public abstract byte getPercentageComplete();

    public abstract int getNumRequests();

    public abstract int getNumErrors();

    public abstract int getNumInsertionPoints();

    public abstract void cancel();

    public abstract IScanIssue[] getIssues();
}

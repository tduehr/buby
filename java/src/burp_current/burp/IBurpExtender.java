// Decompiled by Jad v1.5.8g. Copyright 2001 Pavel Kouznetsov.
// Jad home page: http://www.kpdus.com/jad.html
// Decompiler options: packimports(3) 

package burp;


// Referenced classes of package burp:
//            IBurpExtenderCallbacks

public interface IBurpExtender
{

    public abstract void setCommandLineArgs(String as[]);

    public abstract byte[] processProxyMessage(int i, boolean flag, String s, int j, boolean flag1, String s1, String s2, 
            String s3, String s4, String s5, byte abyte0[], int ai[]);

    public abstract void registerExtenderCallbacks(IBurpExtenderCallbacks iburpextendercallbacks);

    public abstract void applicationClosing();

    public static final int ACTION_FOLLOW_RULES = 0;
    public static final int ACTION_DO_INTERCEPT = 1;
    public static final int ACTION_DONT_INTERCEPT = 2;
    public static final int ACTION_DROP = 3;
}

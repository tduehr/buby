package burp;

import java.net.URL;

public interface IScanIssue
{

  public String getHost();

  public int getPort();

  public String getProtocol();

  public java.net.URL getUrl();

  public String getIssueName();

  public String getSeverity();

  public String getConfidence();

  public String getIssueBackground();

  public String getRemediationBackground();

  public String getIssueDetail();

  public String getRemediationDetail();

  public IHttpRequestResponse[] getHttpMessages();

}

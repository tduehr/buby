package burp;

public interface IScanQueueItem
{

  public String getStatus();

  public byte getPercentageComplete();

  public int getNumRequests();

  public int getNumErrors();

  public int getNumInsertionPoints();

  public void cancel();

  public IScanIssue[] getIssues();

}

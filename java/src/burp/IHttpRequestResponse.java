package burp;

import java.net.URL;

public interface IHttpRequestResponse
{

  public String getHost();

  public int getPort();

  public String getProtocol();

  public void setHost(String host) throws Exception;

  public void setPort(int port) throws Exception;

  public void setProtocol(String protocol) throws Exception;

  public byte[] getRequest() throws Exception;

  public java.net.URL getUrl() throws Exception;

  public void setRequest(byte[] message) throws Exception;

  public byte[] getResponse() throws Exception;

  public void setResponse(byte[] message) throws Exception;

  public short getStatusCode() throws Exception;

}

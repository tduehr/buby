
Burp version 1.2.09 added major enhancements to Burp's extension API.

Details here:
  http://releases.portswigger.net/2009/05/v1209.html

In order to include support for the new Burp features while still maintaining 
compatability with older verions, the buby BurpExtender implementation has 
been split into "branches" and both are included with the distribution.

* current     - Use this if you're using burp 1.2.09 or higher
* pre-1.2.09  - Use this if you're on an earlier version.

The build instructions are the same for both. From the directory where this
README is located first pick your version:

  cd (current or pre-1.2.09)

Then compile and package a JAR into "buby/java" two directories up:

  javac -classpath (path to jruby...)/lib/jruby.jar:. BurpExtender.java
  jar -cvf ../../buby.jar .

You should now be able to proceed with building a gem or a manual install.


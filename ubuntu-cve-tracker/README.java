Useful links:
http://mail.openjdk.java.net/pipermail/distro-pkg-dev/
http://www.oracle.com/technetwork/topics/security/alerts-086861.html
If the alerts- URL dies, look for "Critical Patch Update Advisory":
http://www.oracle.com/technetwork/topics/security/learnmore/index.html


Oracle bought Sun; Java is no longer redistributable, so old Sun JDK and
JRE packages are abandoned.

Oracle provides binary downloads at:

  http://www.oracle.com/technetwork/java/javase/downloads/index.html

These may or may not correspond closely with the OpenJDK opensource
packages being developed at:

  http://openjdk.java.net/
 

In general, when Oracle releases a Critical Patch Update matrix like:

  http://www.oracle.com/technetwork/topics/security/javacpuoct2012-1515924.html#AppendixJAVA

you can also find a more detailed version with a 'text' link:

  http://www.oracle.com/technetwork/topics/security/javacpuoct2012verbose-1515981.html

The more verbose version will go a long way towards helping explain the
severity of the problem, though Oracle does not provide public details.

The IcedTea team provides builds of OpenJDK using Free Software build
tools, PulseAudio support, etc.; their distro-pkg-dev mail list will have
[SECURITY] announcements with lists of bugs and CVE numbers:

  http://mail.openjdk.java.net/pipermail/distro-pkg-dev/2012-October/020571.html
  http://mail.openjdk.java.net/pipermail/distro-pkg-dev/2012-October/020556.html

Look for both IcedTea 6 and IcedTea 7 information; fixes aren't always
available for both immediately.

IceTea tarballs use a forest mechanism and can be found at:
  http://icedtea.classpath.org/hg/release/

(see https://wiki.ubuntu.com/SecurityTeam/PublicationNotes#OpenJDK and/or talk
 to doko for more information)

Java 6 is mostly openjdk-6.

Anything "JDK" or "JRE" from Java would be in openjdk-6.

"Java Web Start" is a closed-source project.  A Free re-implementation
is IcedTea, which is part of openjdk-6.  Vulnerabilities in JWS may
or may not apply to IT.


Patches
-------
openjdk-7
http://hg.openjdk.java.net/jdk7u/jdk7u-dev/jdk/shortlog


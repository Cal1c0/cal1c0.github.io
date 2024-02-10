---
title:  "HTB Keeper Writeup"
date:   2023-12-09 00:30:00 
categories: HTB Machine
tags: Default_credentials keepass CVE-2023-32784
---

![Keeper](/assets/img/Keeper/1691683208749.jpg)

## Introduction

The initial access of this machine is abusing a very common issue in larger environments. There is always one or two devices that didn't have their default credentials changed. The privesc was also trivial but a fun one at least. It abused a bug in the crash dumps of older versions of keepass allowing us to dump the password of the keepass vault

If you like any of my content it would help a lot if you used my referral link to buy Hack The Box/Academy Subscriptions which you can find on my about page.

## Initial access
### Recon

To start off our recon we will begin with an Nmap scan of the machine. Using the following command:
```
sudo nmap -sS -A  -p-  -o nmap  10.10.11.227
```
**Nmap**
```
# Nmap 7.94 scan initiated Thu Dec 28 13:07:28 2023 as: nmap -sS -A -p- -o nmap 10.10.11.227
Nmap scan report for 10.10.11.227
Host is up (0.025s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 35:39:d4:39:40:4b:1f:61:86:dd:7c:37:bb:4b:98:9e (ECDSA)
|_  256 1a:e9:72:be:8b:b1:05:d5:ef:fe:dd:80:d8:ef:c0:66 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: nginx/1.18.0 (Ubuntu)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94%E=4%D=12/28%OT=22%CT=1%CU=42065%PV=Y%DS=2%DC=T%G=Y%TM=658DB9
OS:8F%P=x86_64-pc-linux-gnu)SEQ(SP=103%GCD=1%ISR=105%TI=Z%CI=Z%II=I%TS=9)SE
OS:Q(SP=103%GCD=1%ISR=105%TI=Z%CI=Z%II=I%TS=A)SEQ(SP=103%GCD=2%ISR=105%TI=Z
OS:%CI=Z%II=I%TS=A)OPS(O1=M53CST11NW7%O2=M53CST11NW7%O3=M53CNNT11NW7%O4=M53
OS:CST11NW7%O5=M53CST11NW7%O6=M53CST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%
OS:W5=FE88%W6=FE88)ECN(R=Y%DF=Y%T=40%W=FAF0%O=M53CNNSNW7%CC=Y%Q=)T1(R=Y%DF=
OS:Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%
OS:F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y
OS:%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%R
OS:D=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)I
OS:E(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 110/tcp)
HOP RTT      ADDRESS
1   29.88 ms 10.10.14.1
2   25.33 ms 10.10.11.227

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Dec 28 13:08:15 2023 -- 1 IP address (1 host up) scanned in 47.58 seconds
```

Looking at the nmap output we can see that only the web application port **80** is open here. So lets go check this one out. When I looked at the web page i saw that there was a link present that went to **tickets.keeper.htb**. 

![redirect found](/assets/img/Keeper/Keeper_01.png)

When browsing to this page we are greeted with the following login page. We can see that its using Request tracker When looking online i could find that the default credentials for the **root** account is **password** Entering this password gave us access to the web application.

![Request tracker used](/assets/img/Keeper/Keeper_02.png)

When looking through the application we can find two interesting pages. The first being the recently opened tickets page. which discloses an issue one of the users is having. They are saying they have a crash dump in their home directory to help the admins debug their issues with keepass. This is very interesting information giving us a target to go after once we have access to the system.

![Issue found](/assets/img/Keeper/Keeper_03.png)

Secondly when checking out the users panel of the application we could see that the same user we noticed before in the ticket had a note on her profile. This note mentioned their default starters password. Using this password gave us access to the machine with ssh using the password **Welcome2023!**

![Default password found](/assets/img/Keeper/Keeper_04.png)


```
ssh lnorgaard@keeper.htb 
```

## Privilege escalation

So when we logged into the machine we could see the files that Inorgaard mentioned before in her ticket. My first guess was to extract those files using scp. This zipfile contained both the keyvault as the crashdump.


![Default password found](/assets/img/Keeper/Keeper_05.png)

````
scp lnorgaard@keeper.htb:~/RT30000.zip ./
unzip RT30000.zip
````

So next up i loaded the dump file into [windbg](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/). This tool can be used to analyze the we could find out that the version of keepas used was **2.53.1.0** When looking deeper into this version i could find out that there is a public exploit that allows an attacker to extract the keepass password from a crash dump. [exploit](https://github.com/vdohney/keepass-password-dumper)

![Crashdump analysis](/assets/img/Keeper/Keeper_06.png)


Next up i installed dotnet and ran the proof of concept giving us the following output. This output looked a little weird and didn't match up perfectly however when just googling the password itself we would get a suggestion by google which made sense being **rødgrød med fløde**


![Password obtained](/assets/img/Keeper/Keeper_07.png)




Now that we have the password of the keepass vault we could open it by installing a keepass client. I chose to install the [keeweb](https://keeweb.info/) client. After installing this client and loading our vault into it was able to open it using the password **rødgrød med fløde**.

![keepas opened](/assets/img/Keeper/Keeper_08.png)


In this keyvault we can see an SSH key in putty format. Before we can use this in our linux machine we need to convert it to a plain ssh key. We can do this by loading the key into **puttygen** and then using the conversions tab to convert this to an ssh key 

![Save private key](/assets/img/Keeper/Keeper_09.png)

Now that we have this key all we need to do is to set our permission right and connect with it as the root user.

```
chmod 600 id_rsa
ssh -i id_rsa root@keeper.htb
```

![Root connection](/assets/img/Keeper/Keeper_10.png)

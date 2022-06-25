# Timelapse - Windows Box

**Reconnaissance**

-  `sudo nmap -sC -sV -oN nmap -v -p- 10.10.11.152`

![[Pasted image 20220509213919.png]]

We see an Active Directory listing using LDAP (service associated with Active Directory).

- Kerberos, netbios, and DNS being used within the Active Directory machine.

**Enumerating available shares from the timelapse box**

- `enum4linux timelapse.htb` to find available shares 

![[Pasted image 20220509221643.png]]

From this, we get 'Known Usernames' which is somewhat interesting.

- We also get the domain name TIMELAPSE and domain SID.
**Connecting using smbclient**

![[Pasted image 20220509215543.png]]

You can see we have all these possible shares (sharenames) to connect to within the Active Directory machine.

We can check connection to these shares like: 

![[Pasted image 20220509220120.png]]

Eventually we are able to connect to `IPC$`:

![[Pasted image 20220509220143.png]]

**Pentesting SMB**

Use https://book.hacktricks.xyz/network-services-pentesting/pentesting-smb HackTricks to guide pentesting methodology of smb
![[Pasted image 20220509223236.png]]


![[Pasted image 20220509223017.png]]

Using the smbclient command with a blank password allows us to connect, from which we can see two shares Dev and HelpDesk.


I then navigated to these directories and got everything from them using the `get` command; we find a zip that may be crackable.

![[Pasted image 20220509223510.png]]

![[Pasted image 20220509223602.png]]

Now we need to find out how to crack the zip, which has a password.

For this, i have chosen to use a tool called `fcrackzip` on kali

![[Pasted image 20220509224436.png]]

Using the dictionary `-D` argument, found the password to be *supremelegacy*

After unzipping the zip with the password we got, we get a pfx file, which likely contains an SSL cert and public key.

**Extracting certificate and public key from encrypted .pfx file**

![[Pasted image 20220509225426.png]]

If we had the import password that we used to create the .pfx  file, we could extract the certificate and key using openssl, as above.

- Can we crack the password that was used to encrypt the .pfx file?

**Using crackpkcs12 to crack passwords from pfx files** 

- compiled it using libssl-dev.

- Used dictionary option to test rockyou.txt wordlist against .pfx file

`crackpkcs12 -d /usr/share/wordlists/rockyou.txt ../legacyy_dev_auth.pfx`

- ![[Pasted image 20220509232401.png]]

The tool works successfully, and returns the password thuglegacy

Now we can run the openssl commands with the import password to get the private key and certificate from the .pfx file:


![[Pasted image 20220509232654.png]]

MIIFHDBOBgkqhkiG9w0BBQ0wQTApBgkqhkiG9w0BBQwwHAQIMARIm6lZu7sCAggA
MAwGCCqGSIb3DQIJBQAwFAYIKoZIhvcNAwcECF6ONkp8uSmOBIIEyOAtyru4Pyzw
DGzms5Gxpme2SsgkSd9hRMKpmqZmYKlrK5fW01sBIcdunn/uqb3ZneZnz3ymwmy0
yvaJx7XhP0PaUQY4+7EnAUykxFi5HMYLV8XZ2QyXwv9f7Sgep5Js9TEP1jU8PaL+
1DDYGlwEnL3DAsFfAHKXnlP76tlr1wAx68XJyAmGBBOv0eQlRAWpXLElLKGZjVhV
WleHibCPhzp4+D+iZG9C5bGA3/VEMX9JlaAVqp8hgfGM20WJ8OQgXVfNtu39aEx2
45cVLs2lYD6s++Jus7muTAK1h1HavZHdjg8VZw+Syi6WnwH9LYElrLb7czpryr9a
PdTms9wfoK9V9mTxjnFtegWDrFT1H7nyPXX1w8grS5ZjVJmPAwgqlgzkH0m9jCj4
qh3IoQKe9JAMgwRF8EZWMe7XBYGdb2cD9c76nVJ0TFFd8poKw23xyzvRXge92mRX
VeLfd6t3dlb/FGPbKabrKKgJ7SnE3Fo7khy07/xpsoWdCFDVwZLXFHWFmEFLocVE
+6kIv+8c4Ktx2XrzyEtYA2jZbuSgI0JKylQa+2bGStUxhP+cBedfz1znhpx+njNa
P3vJqnqUyv/hM6XJjGWeFzjdn3f/GA/68Ma0/GAfUDTTQqqLvpQdhmbh4nIWQB/N
t2RRgsVu7YRVc4lawjFYig0BQTMOW8rmcQLJFe7gssJAtzb2EBQm14Mi7zWE2KDH
GbKMd5cdqTQ78kVvc3s4mkJU4Su9J/ZSSY0bXzRYxWJLIE5mC6e9A02MKX91hrQy
AlJvrybCH0aua/GLKIXXAQonUEqL+s6YWHSGfoGljQD4I+wGX/kCWG0mGFBYWVKt
R33kN0duSPx1uxwhr3B7zdQT4MLFXS0SG7hGHXi8s7J0vVw1uQAvyCMtkI0klbiL
yCbjO8n4D6tFzVDG63v5B3IrxO/NFwcFj2aP2HxtpfAykABn5CzzSsMdwhS+isK1
xRBJaQgcTGvj6KCJ+jK5n8YZ6yC24wfszvUr0VgdXkcrdJq9ayJk96qeTqAbcsM4
2tOQ86dEeYni0mA+19x7/pxHpCtT/0DDGQPC9aGGnZLd8UaTFu/d0BhhNn9HkBkH
WA9Hibnauc/VOA69VGftvpMRHjLHgFcaeBn2CwofRt0GmNqywasgILrjYro4DSwe
STHibm8LyGkGZnbZHxirjP3xNYyz/7nY0TxKywEfUCMoy/sh0ifpyEVTLWsfte6i
+TxVBhcU1DfKkUt/S6qHQQ3Ux1//aIyG9sjjqbsY+nwPDWQ1pJ2VhmRi5HQlj1No
D2PtCAVULGhUC9FK5rdKM3qiC0raOTkk/L2nM5ChrbqsuLBEl/gpyPSUwlMjDVA8
sS6o8b30KObEGztE4a4DH1eJDrgO54OHoVBzxl1aRrCjItI57ejDb3c8jyvRNXLt
0nPMQUiRtKf3k3UiCvmuYFC87TWZoPHQoMJWc0zBUa85Cm4HFibkBojk3DlRuCoh
3L2LP37uTqChAX9djwytYPifNu4RoRim/VpSE/nzDtPQAnBYGoFrojN6dbNse+89
Sy1Nuh9WvRMHFGrjjbeOr+hn+ci+HyCoA7HJ5cNV7pgLEsWBvaIC5+HTCe/3d9Rc
Wiy2nxkHnZin9bM5Gw6Mzg==


![[Pasted image 20220509232907.png]]

**Using evil-winrm to connect using private key and certificate**


![[Pasted image 20220509234831.png]]

We are able to connect using the private key and certificate we gained from the .pfx file.

- Once we're on it, we can start navigating and enumerating everything:

   - user.txt: 130c1c0f9a2a39552c8a2338604db563

   - user.txt: 52a1ac599a8c4965339e9d824ab7c1c1

Now that we got the user flag, we need to focus on privesc to get the system flag.


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

The text E3R$Q62^12p7PLlC%KWaxuaV is being made into a secure string; a password is trying to be created

- We can see the environment variables $p (password) and $c (credentials) being created, in which $c is taking arguments of 'svc_deploy' (presumably username) and $p (password).

**Used crackmapexec to connect to domain name controller, and make it leak laps**

- ![[Pasted image 20220511010731.png]]

- Needed to configure default DNS resolution for 10.10.11.152 to timelapse.htb in /etc/hosts

Got onto the machine with admin privileges using evilrm and the new password,
![[Pasted image 20220511011900.png]]

in which i then used Powershell to find the root.txt flag
- ![[Pasted image 20220511011727.png]]

![[Pasted image 20220511011951.png]]

root.txt: 0b68d020c694289c7601b752ef7a1e0d


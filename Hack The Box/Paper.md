# Paper on HTB

- Look at the extension of common directory files in apache website (index.html, robots.txt).

- Try different extension names to see if you can get differing error messages that might show what the source code is filtering for.

- Nmap scan with sV sC oN on ip address

- Fully secure version of OpenSSH located.

- SSL/HTTP running on box. Let's look for certs from SSL.

- Scan brings back a cert with a locally signed domain. 

- Two apache on http and HTTPS.

**Run Dirbuster scan**

- Enumerates possible hidden directories on the machine (with different names and extensions). Brute forces directories.

![](https://f004.backblazeb2.com/file/github-images/Pasted+image+20220424121655.png)

- We use the gobuster tool running the dirbuster mode

- Did the same command as above, but with https.

![](https://f004.backblazeb2.com/file/github-images/Pasted+image+20220424121928.png)

- This found the /manual directory.

- We find out we are in var/www/html directory.

**Nikto**

- Moves onto running *nikto* tool; vulnerability scanner for websites.
![](https://f004.backblazeb2.com/file/github-images/Pasted+image+20220424122248.png)

![](https://f004.backblazeb2.com/file/github-images/Pasted+image+20220424122016.png)
- This found office.paper, an uncommon header 'x-backend-server' with contents office.paper (hostname). This was hidden in the HTTP header.

- Capture the web request to the apache website {10.10.11.143) with Burpsuite.

![](https://f004.backblazeb2.com/file/github-images/Pasted+image+20220424122425.png)

- Edited /etc/hosts file to define his own DNS; inputs the IP address and says that it needs to resolve to office.paper hostname. 

- Now if we type in office.paper, it redirects us to the backend of a server Dunder Tifflin (WordPress)

![](https://f004.backblazeb2.com/file/github-images/Pasted+image+20220424122454.png)

**Scanning WordPress site with wpscan**

- In index.html file, will say something like (`if index.html in url = office.paper > office.paper wordpress`)

- Scan:
![](https://f004.backblazeb2.com/file/github-images/Pasted+image+20220424122603.png)

![](https://f004.backblazeb2.com/file/github-images/Pasted+image+20220424122706.png)

- Found some users, lets create a users file to save potential creds for these.

	...Found jpg, quickly look through it with `strings`

- We then find a website under some blog posts on the website.

- "you should remove secret contents from your drafts, as they are not that secure" with this message, we should look into Wordpress drafts (OSINT).

**Looking at wordpress/login.php**

- Moves onto logging into another wordpress portal by bruteforcing with users with wpscan:

![](https://f004.backblazeb2.com/file/github-images/Pasted+image+20220424123252.png)

- While this login bruteforce is running, we should look at the source code on the blog page.

**Running steganography attacks on the jpg**

- Navigates to *ctfkatana* and looks at some tools that we could run stego on the handshake-michael-1.jpg.

- `sudo apt install steghide` **Using steghide**

First did steganography online to decode the message in the jpg. Doesn't give us any human readable text

`steghide extract -sf handshake-michael-1.jpg` requires entrance of a passphrase

**Stegcracker**

![](https://f004.backblazeb2.com/file/github-images/Pasted+image+20220424124216.png)

Runs stegcracker on it like this. (install: `pip3 install stegcracker`)

**Stegseek**

![](https://f004.backblazeb2.com/file/github-images/Pasted+image+20220424124357.png)

![](https://f004.backblazeb2.com/file/github-images/Pasted+image+20220424124407.png)

**Gobuster office.paper**

- Taking break from stego chaallenge, moves on to gobustering office.paper

**Exploited Wordpress 5.2.3 to find saved drafts**

![](https://f004.backblazeb2.com/file/github-images/Pasted+image+20220424124717.png)

used this exploit: `http://office.paper/?static=1&order=desc` Vulnerability on Wordpress (Viewing unauthenticated/password/private posts)

- From this, we see a secret registration url for new employee chat system

![](https://f004.backblazeb2.com/file/github-images/Pasted+image+20220424124947.png)

- In order to get to chat.office.paper, we need to change our DNS config in /etc/hosts to resolve to that site.

- Brings us to a rocket chat site where we have to register a account.

- After we login, and can see user 'Amy' is online

![](https://f004.backblazeb2.com/file/github-images/Pasted+image+20220424125202.png)


- Here, we find a bot, and are going to look to exploit the bot to potentially gain credentials or look to login during a certain specified time at wordpress/login.php

- One of the things we can do is read files on directory. (File, joke, list...these are bot commands)
![](https://f004.backblazeb2.com/file/github-images/Pasted+image+20220424125721.png)

- Performed directory traversal to navigate backwards out of the current directory to etc, password, from which we catted the password file. 

- We were previously at home/dwight/sales/

- We cannot run OS commands (`whoami ; &`), trying to do command injection.

- `recyclops list ..` lists an .ssh directory 

Trying to look for important stuff using `list` and the bot's command execution. One of the flags was in /dwight/user.txt

- Checking all allowed bot commands for code/command injection (injecting OS commands).

![](https://f004.backblazeb2.com/file/github-images/Pasted+image+20220424130737.png)

- We get output saying 'stop injecting OS commands!' which makes us know it is recognizing the OS commands we are injecting, doesn't necessary mean they are being filtered out.

- Had them reset the box to make sure the .ssh file wasn't deleted. `.ssh` shows private and public key, which we could use to connect to the machine via SSH.

- Still poring through all listable directories to find another flag.

- The bot is a hubot; potentially exploitable?

- Doing some OSINT tells us that depending on the version, we may be able to get code execution on the Hubot.

- Problem is we keep getting a 'Permission Denied' custom error. It is checking for command injection (`|, &, &&, ||, ;`)


- From /hubot we see /.env, in which we can type the file command on to get some credentials 
![](https://f004.backblazeb2.com/file/github-images/Pasted+image+20220424133029.png)

- Logged into dwight so we can access his file share. 

**Linpeas**

- Now moves onto linpeas to privesc to root.

![](https://f004.backblazeb2.com/file/github-images/Pasted+image+20220424133315.png)

- Finds a cronjob running bot_restart.sh on reboot

- Was vulnerable to CVE-2021-3560 (polkit)

- Downloaded script -> vim file.py -> python3 file.py

- This created a new user ahmed, which can execute OS commands. They have full sudo access on the machine. 

- Now we just cat a flag and we are done.

# Pandora Box

**Recon** 

![](https://f004.backblazeb2.com/file/github-images/Pasted+image+20220424135444.png)

![](https://f004.backblazeb2.com/file/github-images/Pasted+image+20220424140327.png)

Start off with Nmap scan, then find a 'Play' website, then run gobuster on it... 

![](https://f004.backblazeb2.com/file/github-images/Pasted+image+20220424141424.png)

- Does `sudo nmap -sU panda.htb -v  -p 161`  to get some actual scan results.

**Enumerating SNMP**

`sudo apt install snmp-mibs-downloader`

- Uses `snmpwn to bruteforce user passwords on panda.htb`

- We have unauthorized access to snmp; use `snmpnum` tool to enumberate passwords from a dude named daniel.

- Able to find him loggin in using ssh.

- Then we use a tool `snmpwalk` to actively monitor actions in snmp session.

- Found Daniel's password using `snmpwalk`.

- Need to exploit Pandora console.





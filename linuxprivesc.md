






![image](https://user-images.githubusercontent.com/35967437/200787298-1e975059-fbe5-4d8a-8313-674bb4e4e67b.png)

<h1>kernel exploits</h1>
if established session with MSFCONSOLE while sessions is established type run post/multi/recon/local_exploit_suggester identify vulnerability and type use exploitname set SESSION [meterpreter SESSION number] set LPORT run <br>
<br>

<h2>Further Paths </h2> <br>
if you find say a cron job or script referencing a system command e.g. cat, run env | grep PATH and take a look at the path. Then run which cat and see where this is being called from, e.g. /bin/cat. <br>
Run a command - touch /bin and see if you can read/write the directory, if so /mv /bin/cat /tmp <br>
Create new file named cat and add reverse shell <br>
This will now be run everytime a cronjob or file references the system command. <br>
<br>
Run find / -perm -u=s -exec ls -l {} \; 2>/dev/null and look for non normal linux binary, e.g. /usr/bin/menu. Have a look if this runs as root. <br>
run strings on the full path - strings /usr/bin/menu and see what is happening, are there system commands being run? <br>
e.g. if curl is being run we can create a vulnerable version of curl. <br>
Create malicious version of curl in /tmp directory and add /tmp to path $ export - export PATH=/tmp:$PATH <br>
Execute the original binary e.g /usr/bin/menu <br>
This happens because path checks left to right every directory specified for the file, new added path directory is first on left


